// @ts-check
/// <reference lib="dom" />
/// <reference types="node" />

/**
 * @typedef {import('node:crypto')} Crypto
 * @typedef {import('node:fs/promises')} FsPromises
 * @typedef {import('fs').PathLike} PathLike
 */

/**
 * @typedef {[string, string]} ChallengeTuple
 */

/**
 * @typedef {Object} ChallengeData
 * @property {Array<ChallengeTuple>} challenge - Array of [salt, target] tuples
 * @property {number} expires - Expiration timestamp
 * @property {string} token - Challenge token
 */

/**
 * @typedef {Object} ChallengeState
 * @property {Record<string, ChallengeData>} challengesList - Map of challenge tokens to challenge data
 * @property {Record<string, number>} tokensList - Map of token hashes to expiration timestamps
 */

/**
 * @typedef {Object} ChallengeConfig
 * @property {number} [challengeCount=50] - Number of challenges to generate
 * @property {number} [challengeSize=32] - Size of each challenge in bytes
 * @property {number} [challengeDifficulty=4] - Difficulty level of the challenge
 * @property {number} [expiresMs=600000] - Time in milliseconds until the challenge expires
 * @property {boolean} [store=true] - Whether to store the challenge in memory
 */

/**
 * @typedef {Object} TokenConfig
 * @property {boolean} [keepToken] - Whether to keep the token after validation
 */

/**
 * @typedef {Object} Solution
 * @property {string} token - The challenge token
 * @property {Array<[string, string, string]>} solutions - Array of [salt, target, solution] tuples
 */

/**
 * @typedef {(key: string) => Promise<any>} CapGetKeyFn
 */
/**
 * @typedef {(key: string, value: any, expires?: number) => Promise<void>} CapSetKeyFn
 */

/**
 * @typedef {Object} CapConfig
 * @property {string} tokens_store_path - Path to store the tokens file
 * @property {ChallengeState} state - State configuration (used if no KV provided)
 * @property {boolean} noFSState - Whether to disable the state file
 * @property {(state: ChallengeState) => Promise<void>} [asyncStoreState] - Optional async function to store state (legacy)
 * @property {() => Promise<ChallengeState>} [asyncLoadState] - Optional async function to load state (legacy)
 * @property {CapGetKeyFn} [getKey] - Optional async key-value read function
 * @property {CapSetKeyFn} [setKey] - Optional async key-value write function
 */

/** @type {typeof import('node:crypto')} */
const crypto = require("crypto");
/** @type {typeof import('node:fs/promises')} */
const fs = require("fs/promises");
const { EventEmitter } = require("events");

const DEFAULT_TOKENS_STORE = ".data/tokensList.json";
const CHALLENGE_PREFIX = "challenge:";
const TOKEN_PREFIX = "token:";

/**
 * Main Cap class
 * @extends EventEmitter
 */
class Cap extends EventEmitter {
  /** @type {Promise<void>|null} */
  _cleanupPromise;

  /** @type {CapConfig} */
  config;

  /** @type {boolean} */
  _useKV;

  /**
   * Creates a new Cap instance
   * @param {Partial<CapConfig>} [configObj] - Configuration object
   */
  constructor(configObj) {
    super();
    this._cleanupPromise = null;
    /** @type {CapConfig} */
    this.config = {
      tokens_store_path: DEFAULT_TOKENS_STORE,
      noFSState: false,
      state: {
        challengesList: {},
        tokensList: {},
      },
      ...configObj,
    };

    this._useKV = typeof this.config.getKey === "function" && typeof this.config.setKey === "function";

    if (this._useKV) {
      // No preloading required; rely on external KV TTLs.
    } else if (this.config.asyncLoadState) {
      this.config.asyncLoadState()
        .then((state) => {
          if (state) this.config.state = state;
        })
        .catch(() => { });
    } else if (!this.config.noFSState) {
      this._loadTokens().catch(() => { });
    }

    process.on("beforeExit", () => this.cleanup());
    ["SIGINT", "SIGTERM", "SIGQUIT"].forEach((signal) => {
      process.once(signal, () => {
        this.cleanup()
          .then(() => process.exit(0))
          .catch(() => process.exit(1));
      });
    });
  }

  /**
   * Generates a new challenge
   * @param {ChallengeConfig} [conf] - Challenge configuration
   * @returns {{ challenge: Array<ChallengeTuple>, token?: string, expires: number }} Challenge data
   */
  createChallenge(conf) {
    this._cleanExpiredTokens();

    /** @type {Array<ChallengeTuple>} */
    const challenges = Array.from(
      { length: (conf && conf.challengeCount) || 50 },
      () =>
        /** @type {ChallengeTuple} */([
        crypto
          .randomBytes(Math.ceil(((conf && conf.challengeSize) || 32) / 2))
          .toString("hex")
          .slice(0, (conf && conf.challengeSize) || 32),
        crypto
          .randomBytes(
            Math.ceil(((conf && conf.challengeDifficulty) || 4) / 2)
          )
          .toString("hex")
          .slice(0, (conf && conf.challengeDifficulty) || 4),
      ])
    );

    const token = crypto.randomBytes(25).toString("hex");
    const expires = Date.now() + ((conf && conf.expiresMs) || 600000);

    if (conf && conf.store === false) {
      return { challenge: challenges, expires };
    }

    if (this._useKV) {
      if (this.config.setKey) {
        const setKey = /** @type {CapSetKeyFn} */ (this.config.setKey);
        setKey(
          CHALLENGE_PREFIX + token,
          { challenge: challenges, expires, token },
          expires - Date.now()
        ).catch(() => { });
      }
    } else {
      this.config.state.challengesList[token] = {
        challenge: challenges,
        expires,
        token,
      };
    }

    return { challenge: challenges, token, expires };
  }

  /**
   * Redeems a challenge solution in exchange for a token
   * @param {Solution} param0 - Challenge solution data
   * @returns {Promise<{success: boolean, message?: string, token?: string, expires?: number}>}
   */
  async redeemChallenge({ token, solutions }) {
    this._cleanExpiredTokens();

    let challengeData;
    if (this._useKV) {
      if (this.config.getKey) {
        const getKey = /** @type {CapGetKeyFn} */ (this.config.getKey);
        challengeData = await getKey(CHALLENGE_PREFIX + token);
      }
    } else {
      challengeData = this.config.state.challengesList[token];
    }
    if (!challengeData || challengeData.expires < Date.now()) {
      if (!this._useKV) delete this.config.state.challengesList[token];
      return { success: false, message: "Challenge expired" };
    }

    if (this._useKV) {
      if (this.config.setKey) {
        const setKeyDel = /** @type {CapSetKeyFn} */ (this.config.setKey);
        await setKeyDel(CHALLENGE_PREFIX + token, null, 0).catch(() => { });
      }
    } else {
      delete this.config.state.challengesList[token];
    }

    const isValid = challengeData.challenge.every(
      /** @param {[string,string]} tuple */
      (tuple) => {
        const salt = tuple[0];
        const target = tuple[1];
        const solution = solutions.find((sol) => sol[0] === salt && sol[1] === target);
        return (
          solution &&
          crypto
            .createHash("sha256")
            .update(salt + solution[2])
            .digest("hex")
            .startsWith(target)
        );
      }
    );

    if (!isValid) return { success: false, message: "Invalid solution" };

    const vertoken = crypto.randomBytes(15).toString("hex");
    const expires = Date.now() + 20 * 60 * 1000;
    const hash = crypto.createHash("sha256").update(vertoken).digest("hex");
    const id = crypto.randomBytes(8).toString("hex");

    if (this._useKV) {
      if (this.config.setKey) {
        const setKeyTok = /** @type {CapSetKeyFn} */ (this.config.setKey);
        await setKeyTok(
          TOKEN_PREFIX + `${id}:${hash}`,
          expires,
          expires - Date.now()
        ).catch(() => { });
      }
    } else {
      if (this?.config?.state?.tokensList) this.config.state.tokensList[`${id}:${hash}`] = expires;

      if (this.config.asyncStoreState) {
        await this.config.asyncStoreState(this.config.state);
      } else if (!this.config.noFSState) {
        await fs.writeFile(
          this.config.tokens_store_path,
          JSON.stringify(this.config.state.tokensList),
          "utf8"
        );
      }
    }

    return { success: true, token: `${id}:${vertoken}`, expires };
  }

  /**
   * Validates a token
   * @param {string} token - The token to validate
   * @param {TokenConfig} [conf] - Validation configuration
   * @returns {Promise<{success: boolean}>}
   */
  async validateToken(token, conf) {
    this._cleanExpiredTokens();

    const [id, vertoken] = token.split(":");
    const hash = crypto.createHash("sha256").update(vertoken).digest("hex");
    const key = `${id}:${hash}`;

    if (this._useKV) {
      const expires = this.config.getKey ? await (/** @type {CapGetKeyFn} */ (this.config.getKey))(TOKEN_PREFIX + key) : undefined;
      if (expires && expires >= Date.now()) {
        if (conf && conf.keepToken) {
          if (this.config.setKey) {
            const delKey = /** @type {CapSetKeyFn} */ (this.config.setKey);
            await delKey(TOKEN_PREFIX + key, null, 0).catch(() => { });
          }
        }
        return { success: true };
      }
      return { success: false };
    }

    await this._waitForTokensList();

    if (this.config.state.tokensList[key]) {
      if (conf && conf.keepToken) {
        if (this.config.setKey) {
          const delKey = /** @type {CapSetKeyFn} */ (this.config.setKey);
          await delKey(TOKEN_PREFIX + key, null, 0).catch(() => { });
        }
        if (this.config.asyncStoreState) {
          await this.config.asyncStoreState(this.config.state);
        } else if (!this.config.noFSState) {
          await fs.writeFile(
            this.config.tokens_store_path,
            JSON.stringify(this.config.state.tokensList),
            "utf8"
          );
        }
      }
      return { success: true };
    }
    return { success: false };
  }

  /**
   * Loads tokens from the storage file
   * @private
   * @returns {Promise<void>}
   */
  async _loadTokens() {
    if (this.config.asyncLoadState) {
      try {
        const state = await this.config.asyncLoadState();
        if (state) this.config.state = state;
        this._cleanExpiredTokens();
        return;
      } catch { }
    }
    try {
      const dirPath = this.config.tokens_store_path
        .split("/")
        .slice(0, -1)
        .join("/");
      if (dirPath) {
        await fs.mkdir(dirPath, { recursive: true });
      }

      try {
        await fs.access(this.config.tokens_store_path);
        const data = await fs.readFile(this.config.tokens_store_path, "utf-8");
        this.config.state.tokensList = JSON.parse(data) || {};
        this._cleanExpiredTokens();
      } catch {
        console.log(`[cap] Tokens file not found, creating a new empty one`);
        await fs.writeFile(this.config.tokens_store_path, "{}", "utf-8");
        this.config.state.tokensList = {};
      }
    } catch (error) {
      console.log(
        `[cap] Couldn't load or write tokens file, using empty state`
      );
      this.config.state.tokensList = {};
    }
  }

  /**
   * Removes expired tokens and challenges from memory
   * @private
   * @returns {boolean} - True if any tokens were changed/removed
   */
  _cleanExpiredTokens() {
    if (this._useKV) return false; // kv store manages TTL
    const now = Date.now();
    let tokensChanged = false;

    for (const k in this.config.state.challengesList) {
      if (this.config.state.challengesList[k].expires < now) {
        delete this.config.state.challengesList[k];
      }
    }

    for (const k in this.config.state.tokensList) {
      if (this.config.state.tokensList[k] < now) {
        delete this.config.state.tokensList[k];
        tokensChanged = true;
      }
    }

    return tokensChanged;
  }

  /**
   * Waits for the tokens list to be initialized
   * @private
   * @returns {Promise<void>}
   */
  _waitForTokensList() {
    if (this._useKV) return Promise.resolve();
    return new Promise((resolve) => {
      const l = () => {
        if (this.config.state.tokensList) {
          return resolve();
        }
        setTimeout(l, 10);
      };
      l();
    });
  }

  /**
   * Cleans up expired tokens and syncs state
   * @returns {Promise<void>}
   */
  async cleanup() {
    if (this._useKV) return; // kv store handles expirations
    if (this._cleanupPromise) return this._cleanupPromise;

    this._cleanupPromise = (async () => {
      const tokensChanged = this._cleanExpiredTokens();

      if (tokensChanged) {
        if (this.config.asyncStoreState) {
          await this.config.asyncStoreState(this.config.state);
        } else {
          await fs.writeFile(
            this.config.tokens_store_path,
            JSON.stringify(this.config.state.tokensList),
            "utf8"
          );
        }
      }
    })();

    return this._cleanupPromise;
  }
}

/** @type {typeof Cap} */
module.exports = Cap;
