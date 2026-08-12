/**
 * Enzhi Crew Automation
 * Instagram -> Heroku -> Make
 */

const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 5000;

/**
 * ======================================================
 * CONFIG
 * ======================================================
 */

const APP_SECRET =
  process.env.APP_SECRET || null;

const VERIFY_TOKEN =
  process.env.WEBHOOK_VERIFY_TOKEN ||
  process.env.TOKEN ||
  null;

const MAKE_WEBHOOK =
  process.env.MAKE_WEBHOOK_URL || null;

let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || null;

const INSTAGRAM_APP_ID =
  process.env.INSTAGRAM_APP_ID || null;

const INSTAGRAM_APP_SECRET =
  process.env.INSTAGRAM_APP_SECRET || null;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI || null;

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  process.env.APP_SECRET ||
  null;

const INSTAGRAM_API_VERSION =
  process.env.INSTAGRAM_API_VERSION || "v26.0";

let receivedUpdates = [];


/**
 * ======================================================
 * BODY PARSER
 * ======================================================
 *
 * Сохраняем оригинальное тело запроса.
 * Оно потребуется для проверки подписи Meta.
 */

app.use(
  bodyParser.json({
    verify: function (req, res, buf) {
      req.rawBody = Buffer.from(buf);
    },
  })
);
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
let received_updates = [];
let sent_messages = [];
/**
 * ======================================================
 * HELPERS
 * ======================================================
 */

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
function getRecentInstagramMessages() {
  const messages = [];

  for (const update of received_updates) {
    if (
      !update ||
      update.object !== "instagram"
    ) {
      continue;
    }

    const entries =
      Array.isArray(update.entry)
        ? update.entry
        : [];

    for (const entry of entries) {
      const events =
        Array.isArray(entry.messaging)
          ? entry.messaging
          : [];

      for (const event of events) {
        /*
         * Нам нужны только реальные
         * входящие сообщения.
         */
        if (!event.message) {
          continue;
        }

        if (event.message.is_echo) {
          continue;
        }

        const text =
          typeof event.message.text === "string"
            ? event.message.text
            : "";

        if (!text) {
          continue;
        }

        messages.push({
          senderId:
            String(
              event.sender?.id || ""
            ),

          recipientId:
            String(
              event.recipient?.id || ""
            ),

          text: text,

          timestamp:
            Number(
              event.timestamp || 0
            ),

          messageId:
            String(
              event.message?.mid || ""
            ),
        });
      }
    }
  }

  return messages.slice(0, 30);
}

function toBase64Url(value) {
  return value
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


/**
 * Создание state для Instagram OAuth.
 */

function createOAuthState() {
  if (!OAUTH_STATE_SECRET) {
    throw new Error(
      "OAUTH_STATE_SECRET is not configured"
    );
  }

  const timestamp =
    Date.now().toString();

  const randomValue =
    toBase64Url(
      crypto.randomBytes(24)
    );

  const payload =
    `${timestamp}.${randomValue}`;

  const signature =
    toBase64Url(
      crypto
        .createHmac(
          "sha256",
          OAUTH_STATE_SECRET
        )
        .update(payload)
        .digest()
    );

  return `${payload}.${signature}`;
}


/**
 * Проверка state после возврата из Instagram.
 */

function validateOAuthState(state) {
  if (!state || !OAUTH_STATE_SECRET) {
    return false;
  }

  const parts =
    String(state).split(".");

  if (parts.length !== 3) {
    return false;
  }

  const timestamp =
    Number(parts[0]);

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const stateAge =
    Date.now() - timestamp;

  /**
   * State действителен 10 минут.
   */
  if (
    stateAge < 0 ||
    stateAge > 10 * 60 * 1000
  ) {
    return false;
  }

  const payload =
    `${parts[0]}.${parts[1]}`;

  const expectedSignature =
    toBase64Url(
      crypto
        .createHmac(
          "sha256",
          OAUTH_STATE_SECRET
        )
        .update(payload)
        .digest()
    );

  const receivedBuffer =
    Buffer.from(
      parts[2],
      "utf8"
    );

  const expectedBuffer =
    Buffer.from(
      expectedSignature,
      "utf8"
    );

  if (
    receivedBuffer.length !==
    expectedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    receivedBuffer,
    expectedBuffer
  );
}


/**
 * ======================================================
 * META SIGNATURE
 * ======================================================
 *
 * Проверяет подпись входящего webhook.
 *
 * Поддерживаем:
 *
 * X-Hub-Signature-256
 * X-Hub-Signature
 */

function verifyMetaSignature(req) {
  if (!APP_SECRET) {
    console.error(
      "APP_SECRET is not configured"
    );

    return false;
  }

  if (!req.rawBody) {
    console.error(
      "Raw webhook body is missing"
    );

    return false;
  }

  const signature256 =
    req.headers[
      "x-hub-signature-256"
    ];

  const signature1 =
    req.headers[
      "x-hub-signature"
    ];

  let receivedSignature;
  let algorithm;
  let prefix;

  if (signature256) {

    receivedSignature =
      String(signature256);

    algorithm = "sha256";

    prefix = "sha256=";

  } else if (signature1) {

    receivedSignature =
      String(signature1);

    algorithm = "sha1";

    prefix = "sha1=";

  } else {

    console.error(
      "Meta webhook signature header is missing"
    );

    return false;
  }


  const expectedSignature =
    prefix +
    crypto
      .createHmac(
        algorithm,
        APP_SECRET
      )
      .update(req.rawBody)
      .digest("hex");


  const receivedBuffer =
    Buffer.from(
      receivedSignature,
      "utf8"
    );

  const expectedBuffer =
    Buffer.from(
      expectedSignature,
      "utf8"
    );


  if (
    receivedBuffer.length !==
    expectedBuffer.length
  ) {
    return false;
  }


  return crypto.timingSafeEqual(
    receivedBuffer,
    expectedBuffer
  );
}


/**
 * Запоминаем последние события.
 */

function rememberUpdate(body) {
  receivedUpdates.unshift(body);

  if (receivedUpdates.length > 100) {
    receivedUpdates =
      receivedUpdates.slice(
        0,
        100
      );
  }
}


/**
 * ======================================================
 * MAIN PAGE
 * ======================================================
 */

app.get("/", function (req, res) {
  return res.redirect(
    "/instagram-admin"
  );
});


/**
 * ======================================================
 * HEALTH CHECK
 * ======================================================
 */

app.get(
  "/health",
  function (req, res) {

    return res
      .status(200)
      .json({
        status: "ok",
        service:
          "Enzhi Crew Automation",
      });
  }
);


/**
 * ======================================================
 * INSTAGRAM ADMIN
 * ======================================================
 */

app.get(
  "/instagram-admin",
  async function (req, res) {

    res.set(
      "Cache-Control",
      "no-store"
    );

    let account = null;

    let errorMessage = null;


    if (!instagramAccessToken) {

      errorMessage =
        "Переменная INSTAGRAM_ACCESS_TOKEN не задана в Heroku.";

    } else {

      try {

        const response =
          await axios.get(
            `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/me`,
            {
              params: {
                fields:
                  "user_id,username",
              },

              headers: {
                Authorization:
                  `Bearer ${instagramAccessToken}`,

                Accept:
                  "application/json",
              },

              timeout: 10000,
            }
          );


        account = {

          username:
            response.data.username ||
            "unknown",

          userId:
            response.data.user_id ||
            response.data.id ||
            "unknown",
        };


      } catch (error) {

        console.error(
          "Instagram profile request failed"
        );


        if (error.response) {

          console.error(
            JSON.stringify(
              error.response.data,
              null,
              2
            )
          );


          errorMessage =
            error.response.data
              ?.error
              ?.message ||

            `Instagram API returned HTTP ${error.response.status}`;

        } else {

          console.error(
            error.message
          );

          errorMessage =
            error.message ||
            "Не удалось обратиться к Instagram API.";
        }
      }
    }


    const accountBlock =
      account

        ? `
          <div class="account-card">

            <div class="connection-heading">

              <span
                class="status-dot"
              ></span>

              <strong>
                Connected account
              </strong>

            </div>


            <div class="username">
              @${escapeHtml(
                account.username
              )}
            </div>


            <div class="data-row">

              <span>
                Account ID
              </span>

              <strong>
                ${escapeHtml(
                  account.userId
                )}
              </strong>

            </div>


            <div class="data-row">

              <span>
                Status
              </span>

              <strong
                class="connected"
              >
                Connected
              </strong>

            </div>

          </div>
        `

        : `
          <div class="error-card">

            <strong>
              Instagram account is not connected
            </strong>

            <p>
              ${escapeHtml(
                errorMessage
              )}
            </p>

          </div>
        `;


    const buttonText =
      account
        ? "Reconnect Instagram Account"
        : "Connect Instagram Account";


    return res
      .status(200)
      .send(`
        <!DOCTYPE html>

        <html lang="en">

        <head>

          <meta charset="UTF-8">

          <meta
            name="viewport"
            content="
              width=device-width,
              initial-scale=1.0
            "
          >

          <title>
            Enzhi Crew Automation
          </title>


          <style>

            * {
              box-sizing:
                border-box;
            }


            body {
              margin: 0;

              min-height:
                100vh;

              display:
                flex;

              align-items:
                center;

              justify-content:
                center;

              padding:
                24px;

              background:
                #f5f6f8;

              color:
                #182230;

              font-family:
                Arial,
                Helvetica,
                sans-serif;
            }


            .container {

              width:
                100%;

              max-width:
                620px;

              padding:
                40px;

              background:
                #ffffff;

              border-radius:
                18px;

              box-shadow:
                0 16px 45px
                rgba(
                  0,
                  0,
                  0,
                  0.09
                );
            }


            h1 {

              margin:
                0 0 10px;

              font-size:
                31px;
            }


            .description {

              margin:
                0 0 26px;

              color:
                #667085;

              line-height:
                1.55;
            }


            .connect-button {

              display:
                inline-block;

              margin-bottom:
                28px;

              padding:
                14px 22px;

              border-radius:
                10px;

              background:
                #0866ff;

              color:
                #ffffff;

              font-weight:
                700;

              text-decoration:
                none;
            }


            .connect-button:hover {

              background:
                #0759dc;
            }


            .account-card,
            .error-card {

              padding:
                24px;

              border:
                1px solid #dfe3e8;

              border-radius:
                14px;
            }


            .connection-heading {

              display:
                flex;

              align-items:
                center;

              gap:
                10px;

              margin-bottom:
                18px;
            }


            .status-dot {

              width:
                11px;

              height:
                11px;

              border-radius:
                50%;

              background:
                #12b76a;
            }


            .username {

              margin-bottom:
                22px;

              font-size:
                26px;

              font-weight:
                700;
            }


            .data-row {

              display:
                flex;

              justify-content:
                space-between;

              gap:
                20px;

              padding:
                13px 0;

              border-top:
                1px solid #eeeeee;
            }


            .data-row span {

              color:
                #667085;
            }


            .connected {

              color:
                #079455;
            }


            .error-card {

              background:
                #fff5f5;

              border-color:
                #f4b4b4;
            }


            .error-card p {

              margin-bottom:
                0;

              overflow-wrap:
                anywhere;
            }


            .notice {

              margin-top:
                20px;

              color:
                #667085;

              font-size:
                13px;

              line-height:
                1.5;
            }

          </style>

        </head>


        <body>

          <main class="container">

            <h1>
              Enzhi Crew Automation
            </h1>


            <p class="description">

              Connect and manage an
              Instagram professional
              account.

            </p>


            <a
              class="connect-button"
              href="/auth/instagram"
            >

              ${buttonText}

            </a>


            ${accountBlock}


            <p class="notice">

              Instagram profile
              information is used only
              to identify the connected
              professional account.

            </p>

          </main>

        </body>

        </html>
      `);
  }
);


/**
 * ======================================================
 * INSTAGRAM OAUTH START
 * ======================================================
 */

app.get(
  "/auth/instagram",
  function (req, res) {

    const missingVariables = [];


    if (!INSTAGRAM_APP_ID) {

      missingVariables.push(
        "INSTAGRAM_APP_ID"
      );
    }


    if (!INSTAGRAM_APP_SECRET) {

      missingVariables.push(
        "INSTAGRAM_APP_SECRET"
      );
    }


    if (!INSTAGRAM_REDIRECT_URI) {

      missingVariables.push(
        "INSTAGRAM_REDIRECT_URI"
      );
    }


    if (!OAUTH_STATE_SECRET) {

      missingVariables.push(
        "OAUTH_STATE_SECRET"
      );
    }


    if (
      missingVariables.length > 0
    ) {

      return res
        .status(500)
        .send(`

          <h2>
            Instagram OAuth
            is not configured
          </h2>

          <p>
            Missing Heroku Config Vars:
          </p>

          <pre>
${escapeHtml(
  missingVariables.join("\n")
)}
          </pre>

          <p>
            <a href="/instagram-admin">
              Return to
              Enzhi Crew Automation
            </a>
          </p>
        `);
    }


    let state;


    try {

      state =
        createOAuthState();

    } catch (error) {

      console.error(
        "Unable to create OAuth state:",
        error.message
      );


      return res
        .status(500)
        .send(`

          <h2>
            Instagram OAuth
            is not configured
          </h2>

          <p>
            ${escapeHtml(
              error.message
            )}
          </p>

          <p>
            <a href="/instagram-admin">
              Return
            </a>
          </p>
        `);
    }


    const parameters =
      new URLSearchParams({

        client_id:
          INSTAGRAM_APP_ID,

        redirect_uri:
          INSTAGRAM_REDIRECT_URI,

        response_type:
          "code",

        scope: [

          "instagram_business_basic",

          "instagram_business_manage_messages",

          "instagram_business_manage_comments",

        ].join(","),
   
        force_reauth:
      "true",

        state:
          state,
      });


    const authorizationUrl =
      "https://www.instagram.com/oauth/authorize?" +
      parameters.toString();


    return res.redirect(
      authorizationUrl
    );
  }
);


/**
 * ======================================================
 * INSTAGRAM OAUTH CALLBACK
 * ======================================================
 */

app.get(
  "/auth/instagram/callback",

  async function (req, res) {

   console.log(
  "Instagram OAuth callback received",
  {
    queryKeys: Object.keys(req.query),

    hasCode:
      typeof req.query.code === "string" &&
      req.query.code.length > 0,

    hasState:
      typeof req.query.state === "string" &&
      req.query.state.length > 0,

    error:
      req.query.error || null,

    errorReason:
      req.query.error_reason || null,

    errorDescription:
      req.query.error_description || null,

    userAgent:
      req.headers["user-agent"] || null,

    referer:
      req.headers["referer"] || null,
  }
);


    const authorizationCode =
      req.query.code;

    const returnedState =
      req.query.state;


    /**
     * Instagram вернул ошибку.
     */

    if (req.query.error) {

      return res
        .status(400)
        .send(`

          <h2>
            Instagram authorization cancelled
          </h2>

          <p>
            ${escapeHtml(
              req.query
                .error_description ||

              req.query
                .error_reason ||

              req.query.error
            )}
          </p>

          <p>
            <a href="/instagram-admin">
              Return
            </a>
          </p>
        `);
    }


    /**
     * Нет authorization code.
     */

    if (!authorizationCode) {

      return res
        .status(400)
        .send(`

          <h2>
            Authorization code
            is missing
          </h2>

          <p>
            Instagram did not
            return an authorization
            code.
          </p>

          <p>
            <a href="/instagram-admin">
              Return
            </a>
          </p>
        `);
    }


    /**
     * Проверяем state.
     */

    if (
      !validateOAuthState(
        returnedState
      )
    ) {

      return res
        .status(403)
        .send(`

          <h2>
            Invalid OAuth state
          </h2>

          <p>
            Start the Instagram
            connection again.
          </p>

          <p>
            <a href="/instagram-admin">
              Return
            </a>
          </p>
        `);
    }


    try {

      const cleanCode =
        String(
          authorizationCode
        ).replace(
          /#_$/,
          ""
        );


      const tokenForm =
        new URLSearchParams();


      tokenForm.append(
        "client_id",
        INSTAGRAM_APP_ID
      );


      tokenForm.append(
        "client_secret",
        INSTAGRAM_APP_SECRET
      );


      tokenForm.append(
        "grant_type",
        "authorization_code"
      );


      tokenForm.append(
        "redirect_uri",
        INSTAGRAM_REDIRECT_URI
      );


      tokenForm.append(
        "code",
        cleanCode
      );


      /**
       * Получаем short-lived token.
       */

      const shortTokenResponse =
        await axios.post(

          "https://api.instagram.com/oauth/access_token",

          tokenForm.toString(),

          {

            headers: {

              "Content-Type":
                "application/x-www-form-urlencoded",
            },

            timeout:
              15000,
          }
        );


      const shortToken =
        shortTokenResponse
          .data
          .access_token;


      if (!shortToken) {

        throw new Error(
          "Instagram did not return an access token"
        );
      }


      let finalToken =
        shortToken;


      /**
       * Пробуем получить long-lived token.
       */

      try {

        const longTokenResponse =
          await axios.get(

            "https://graph.instagram.com/access_token",

            {

              params: {

                grant_type:
                  "ig_exchange_token",

                client_secret:
                  INSTAGRAM_APP_SECRET,

                access_token:
                  shortToken,
              },

              timeout:
                15000,
            }
          );


        if (
          longTokenResponse
            .data
            .access_token
        ) {

          finalToken =
            longTokenResponse
              .data
              .access_token;
        }


      } catch (
        longTokenError
      ) {

        console.error(
          "Long-lived token exchange failed"
        );


        if (
          longTokenError.response
        ) {

          console.error(
            JSON.stringify(
              longTokenError
                .response
                .data,
              null,
              2
            )
          );

        } else {

          console.error(
            longTokenError.message
          );
        }
      }


      /**
       * Временно сохраняем токен
       * в памяти Heroku dyno.
       *
       * После перезапуска снова
       * используется Config Var:
       *
       * INSTAGRAM_ACCESS_TOKEN
       */

      instagramAccessToken =
        finalToken;


      return res.redirect(
        "/instagram-admin?connected=1"
      );


    } catch (error) {

      console.error(
        "Instagram OAuth callback failed"
      );


      let errorMessage =
        error.message;


      if (error.response) {

        console.error(
          JSON.stringify(
            error.response.data,
            null,
            2
          )
        );


        errorMessage =

          error.response
            .data
            ?.error_message ||

          error.response
            .data
            ?.error
            ?.message ||

          `Instagram returned HTTP ${error.response.status}`;
      }


      return res
        .status(500)
        .send(`

          <h2>
            Instagram connection failed
          </h2>

          <p>
            ${escapeHtml(
              errorMessage
            )}
          </p>

          <p>
            <a href="/instagram-admin">
              Try again
            </a>
          </p>
        `);
    }
  }
);


/**
 * ======================================================
 * INSTAGRAM WEBHOOK VERIFICATION
 * ======================================================
 *
 * Meta вызывает этот GET
 * при настройке Callback URL.
 */

app.get(
  "/instagram",

  function (req, res) {

    const mode =
      req.query[
        "hub.mode"
      ];

    const receivedToken =
      req.query[
        "hub.verify_token"
      ];

    const challenge =
      req.query[
        "hub.challenge"
      ];


    console.log(
      "Instagram webhook verification request",
      {

        mode:
          mode || null,

        hasToken:
          Boolean(
            receivedToken
          ),

        tokenMatches:
          Boolean(
            VERIFY_TOKEN
          ) &&
          receivedToken ===
            VERIFY_TOKEN,

        hasChallenge:
          Boolean(
            challenge
          ),
      }
    );


    if (
      mode === "subscribe" &&

      VERIFY_TOKEN &&

      receivedToken ===
        VERIFY_TOKEN &&

      challenge
    ) {

      console.log(
        "Instagram webhook verified successfully"
      );


      return res
        .status(200)
        .type("text/plain")
        .send(
          String(
            challenge
          )
        );
    }


    console.log(
      "Instagram webhook verification failed"
    );


    return res
      .status(403)
      .type("text/plain")
      .send(
        "Verification failed"
      );
  }
);


/**
 * ======================================================
 * FACEBOOK WEBHOOK VERIFICATION
 * ======================================================
 */

app.get(
  "/facebook",

  function (req, res) {

    const mode =
      req.query[
        "hub.mode"
      ];

    const receivedToken =
      req.query[
        "hub.verify_token"
      ];

    const challenge =
      req.query[
        "hub.challenge"
      ];


    if (
      mode === "subscribe" &&

      VERIFY_TOKEN &&

      receivedToken ===
        VERIFY_TOKEN &&

      challenge
    ) {

      return res
        .status(200)
        .type("text/plain")
        .send(
          String(
            challenge
          )
        );
    }


    return res.sendStatus(
      403
    );
  }
);


/**
 * ======================================================
 * THREADS WEBHOOK VERIFICATION
 * ======================================================
 */

app.get(
  "/threads",

  function (req, res) {

    const mode =
      req.query[
        "hub.mode"
      ];

    const receivedToken =
      req.query[
        "hub.verify_token"
      ];

    const challenge =
      req.query[
        "hub.challenge"
      ];


    if (
      mode === "subscribe" &&

      VERIFY_TOKEN &&

      receivedToken ===
        VERIFY_TOKEN &&

      challenge
    ) {

      return res
        .status(200)
        .type("text/plain")
        .send(
          String(
            challenge
          )
        );
    }


    return res.sendStatus(
      403
    );
  }
);


/**
 * ======================================================
 * FACEBOOK POST WEBHOOK
 * ======================================================
 */

app.post(
  "/facebook",

  function (req, res) {

    console.log(
      "Facebook request body:"
    );

    console.log(
      JSON.stringify(
        req.body,
        null,
        2
      )
    );


    if (
      !verifyMetaSignature(req)
    ) {

      console.log(
        "Invalid Facebook webhook signature"
      );

      return res.sendStatus(
        401
      );
    }


    rememberUpdate(
      req.body
    );


    return res.sendStatus(
      200
    );
  }
);


/**
 * ======================================================
 * INSTAGRAM POST WEBHOOK
 * ======================================================
 */

app.post(
  "/instagram",

  async function (req, res) {

    console.log(
      "======================================="
    );

    console.log(
      "Instagram Webhook received"
    );

    console.log(
      JSON.stringify(
        req.body,
        null,
        2
      )
    );


    /**
     * Проверяем подпись Meta.
     */

    if (
      !verifyMetaSignature(req)
    ) {

      console.log(
        "Invalid Instagram webhook signature"
      );

      return res.sendStatus(
        401
      );
    }


    rememberUpdate(
      req.body
    );


    /**
     * Сначала отвечаем Meta.
     */

    res.sendStatus(
      200
    );


    /**
     * После этого пересылаем
     * событие в Make.
     */

    try {

      if (!MAKE_WEBHOOK) {

        throw new Error(
          "MAKE_WEBHOOK_URL is not configured in Heroku"
        );
      }


      await axios.post(

        MAKE_WEBHOOK,

        req.body,

        {

          headers: {

            "Content-Type":
              "application/json",
          },

          timeout:
            15000,
        }
      );


      console.log(
        "Successfully sent to Make"
      );


    } catch (error) {

      console.error(
        "Error sending to Make"
      );


      if (error.response) {

        console.error(
          JSON.stringify(
            error.response.data,
            null,
            2
          )
        );

      } else {

        console.error(
          error.message
        );
      }
    }
  }
);


/**
 * ======================================================
 * THREADS POST WEBHOOK
 * ======================================================
 */

app.post(
  "/threads",

  function (req, res) {

    console.log(
      "Threads request body:"
    );

    console.log(
      JSON.stringify(
        req.body,
        null,
        2
      )
    );


    rememberUpdate(
      req.body
    );


    return res.sendStatus(
      200
    );
  }
);
/**
 * Instagram deauthorization callback
 */
app.post(
  "/instagram/deauthorize",
  function (req, res) {

    console.log(
      "Instagram deauthorization received"
    );

    console.log(
      JSON.stringify(req.body, null, 2)
    );

    return res.sendStatus(200);
  }
);


/**
 * Instagram data deletion callback
 */
app.post(
  "/instagram/data-deletion",
  function (req, res) {

    console.log(
      "Instagram data deletion request received"
    );

    const confirmationCode =
      crypto
        .randomBytes(12)
        .toString("hex");

    return res.status(200).json({
      url:
        `https://${req.get("host")}/instagram/data-deletion/status?code=${confirmationCode}`,

      confirmation_code:
        confirmationCode,
    });
  }
);


/**
 * Instagram data deletion status
 */
app.get(
  "/instagram/data-deletion/status",
  function (req, res) {

    return res.status(200).send(`
      <h2>
        Data deletion request
      </h2>

      <p>
        Your Instagram data deletion
        request has been received.
      </p>

      <p>
        Confirmation code:
        ${escapeHtml(
          req.query.code || ""
        )}
      </p>
    `);
  }
);

/**
 * Страница Instagram Direct.
 */
app.get(
  "/instagram-messages",
  function (req, res) {
    res.set(
      "Cache-Control",
      "no-store"
    );

    const messages =
      getRecentInstagramMessages();

    const sentSuccessfully =
      req.query.sent === "1";

    const subscribedSuccessfully =
      req.query.subscribed === "1";

    const errorMessage =
      req.query.error
        ? String(req.query.error)
        : null;


    const incomingHtml =
      messages.length > 0
        ? messages
            .map(function (message) {

              let time = "";

              if (message.timestamp) {
                try {
                  time =
                    new Date(
                      message.timestamp
                    ).toLocaleString(
                      "ru-RU"
                    );
                } catch (_) {
                  time = "";
                }
              }

              return `
                <div class="message-card">

                  <div class="message-header">

                    <strong>
                      Incoming message
                    </strong>

                    ${
                      time
                        ? `
                          <span class="time">
                            ${escapeHtml(time)}
                          </span>
                        `
                        : ""
                    }

                  </div>


                  <div class="label">
                    Instagram user ID
                  </div>

                  <div class="sender">
                    ${escapeHtml(
                      message.senderId
                    )}
                  </div>


                  <div class="label">
                    Message
                  </div>

                  <div class="message-text">
                    ${escapeHtml(
                      message.text
                    )}
                  </div>


                  <form
                    method="POST"
                    action="/instagram-messages/send"
                  >

                    <input
                      type="hidden"
                      name="recipientId"
                      value="${escapeHtml(
                        message.senderId
                      )}"
                    >


                    <label>
                      Reply
                    </label>

                    <textarea
                      name="text"
                      placeholder="Type your reply..."
                      required
                    ></textarea>


                    <button
                      type="submit"
                      class="reply-button"
                    >
                      Send Reply
                    </button>

                  </form>

                </div>
              `;
            })
            .join("")
        : `
          <div class="empty-card">

            <strong>
              No incoming messages yet
            </strong>

            <p>
              Send a Direct message to the
              connected Instagram account
              from another Instagram account.
            </p>

          </div>
        `;


    const sentHtml =
      sent_messages.length > 0
        ? sent_messages
            .slice(0, 10)
            .map(function (message) {
              return `
                <div class="sent-message">

                  <strong>
                    Sent to
                    ${escapeHtml(
                      message.recipientId
                    )}
                  </strong>

                  <div>
                    ${escapeHtml(
                      message.text
                    )}
                  </div>

                </div>
              `;
            })
            .join("")
        : `
          <p class="muted">
            No replies sent during this
            server session.
          </p>
        `;


    res.status(200).send(`
      <!DOCTYPE html>

      <html lang="en">

        <head>

          <meta charset="UTF-8">

          <meta
            name="viewport"
            content="width=device-width,
                     initial-scale=1.0"
          >

          <title>
            Instagram Messages
          </title>


          <style>

            * {
              box-sizing: border-box;
            }


            body {
              margin: 0;
              padding: 30px;
              background: #f5f6f8;
              color: #182230;

              font-family:
                Arial,
                Helvetica,
                sans-serif;
            }


            .container {
              max-width: 850px;
              margin: 0 auto;
            }


            h1 {
              margin-bottom: 6px;
            }


            .subtitle {
              color: #667085;
              margin-bottom: 25px;
            }


            .top-actions {
              display: flex;
              gap: 12px;
              flex-wrap: wrap;
              margin-bottom: 24px;
            }


            .button {
              display: inline-block;
              padding: 11px 16px;
              border: 0;
              border-radius: 9px;
              background: #0866ff;
              color: white;
              text-decoration: none;
              cursor: pointer;
              font-weight: 700;
              font-size: 14px;
            }


            .secondary {
              background: #344054;
            }


            .message-card,
            .empty-card {
              background: white;
              border: 1px solid #e4e7ec;
              border-radius: 14px;
              padding: 22px;
              margin-bottom: 18px;
            }


            .message-header {
              display: flex;
              justify-content:
                space-between;
              gap: 15px;
              margin-bottom: 20px;
            }


            .time {
              color: #667085;
              font-size: 13px;
            }


            .label {
              color: #667085;
              font-size: 12px;
              margin-top: 12px;
              margin-bottom: 5px;
            }


            .sender {
              font-weight: 700;
            }


            .message-text {
              padding: 14px;
              background: #f9fafb;
              border-radius: 9px;
              line-height: 1.5;
              margin-bottom: 20px;
              white-space: pre-wrap;
            }


            textarea {
              display: block;
              width: 100%;
              min-height: 90px;
              resize: vertical;

              margin-top: 7px;
              margin-bottom: 12px;

              padding: 12px;

              border: 1px solid #d0d5dd;
              border-radius: 9px;

              font-family: inherit;
              font-size: 14px;
            }


            .reply-button {
              padding: 11px 18px;
              border: 0;
              border-radius: 9px;
              background: #12b76a;
              color: white;
              font-weight: 700;
              cursor: pointer;
            }


            .success {
              padding: 14px;
              margin-bottom: 18px;
              border-radius: 10px;
              background: #ecfdf3;
            }


            .error {
              padding: 14px;
              margin-bottom: 18px;
              border-radius: 10px;
              background: #fff1f0;
            }


            .sent-message {
              background: white;
              border: 1px solid #e4e7ec;
              border-radius: 10px;
              padding: 14px;
              margin-bottom: 10px;
            }


            .sent-message div {
              margin-top: 8px;
            }


            .muted {
              color: #667085;
            }

          </style>

        </head>


        <body>

          <main class="container">

            <h1>
              Instagram Messages
            </h1>


            <p class="subtitle">
              Enzhi Crew Automation
            </p>


            <div class="top-actions">

              <a
                class="button secondary"
                href="/instagram-admin"
              >
                Instagram Account
              </a>


              <a
                class="button"
                href="/instagram-messages"
              >
                Refresh Messages
              </a>


              <form
                method="POST"
                action="/instagram-messages/subscribe"
                style="margin:0"
              >

                <button
                  class="button"
                  type="submit"
                >
                  Enable Message Webhooks
                </button>

              </form>

            </div>


            ${
              sentSuccessfully
                ? `
                  <div class="success">
                    Message sent successfully.
                  </div>
                `
                : ""
            }


            ${
              subscribedSuccessfully
                ? `
                  <div class="success">
                    Instagram account subscribed
                    to message webhooks.
                  </div>
                `
                : ""
            }


            ${
              errorMessage
                ? `
                  <div class="error">
                    ${escapeHtml(
                      errorMessage
                    )}
                  </div>
                `
                : ""
            }


            <h2>
              Incoming
            </h2>

            ${incomingHtml}


            <h2>
              Sent replies
            </h2>

            ${sentHtml}

          </main>

        </body>

      </html>
    `);
  }
);


/**
 * Подписываем подключённый Instagram
 * аккаунт на webhook messages.
 */
app.post(
  "/instagram-messages/subscribe",
  async function (req, res) {

    if (!instagramAccessToken) {
      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(
          "Instagram access token is missing."
        )
      );
    }


    try {

      /*
       * Сначала узнаём ID
       * подключённого Instagram аккаунта.
       */
      const profileResponse =
        await axios.get(
          `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/me`,
          {
            params: {
              fields:
                "user_id,username",
            },

            headers: {
              Authorization:
                `Bearer ${instagramAccessToken}`,
            },

            timeout: 15000,
          }
        );


      const instagramUserId =
        profileResponse.data.user_id ||
        profileResponse.data.id;


      if (!instagramUserId) {
        throw new Error(
          "Instagram account ID was not returned."
        );
      }


      /*
       * Включаем webhook messages
       * для конкретного Instagram аккаунта.
       */
      await axios.post(
        `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/${instagramUserId}/subscribed_apps`,
        null,
        {
          params: {
            subscribed_fields:
              "messages",

            access_token:
              instagramAccessToken,
          },

          timeout: 15000,
        }
      );


      console.log(
        "Instagram messages webhook subscription enabled",
        {
          instagramUserId:
            instagramUserId,
        }
      );


      return res.redirect(
        "/instagram-messages?subscribed=1"
      );

    } catch (error) {

      console.log(
        "Instagram webhook subscription failed"
      );


      let message =
        error.message ||
        "Webhook subscription failed.";


      if (error.response) {

        console.log(
          JSON.stringify(
            error.response.data,
            null,
            2
          )
        );


        message =
          error.response.data
            ?.error?.message ||
          message;
      }


      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(message)
      );
    }
  }
);


/**
 * Отправляем ответ пользователю
 * через Instagram Messaging API.
 */
app.post(
  "/instagram-messages/send",
  async function (req, res) {

    const recipientId =
      String(
        req.body.recipientId || ""
      ).trim();


    const text =
      String(
        req.body.text || ""
      ).trim();


    if (!instagramAccessToken) {

      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(
          "Instagram access token is missing."
        )
      );
    }


    if (!recipientId) {

      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(
          "Recipient Instagram ID is missing."
        )
      );
    }


    if (!text) {

      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(
          "Message text is empty."
        )
      );
    }


    /*
     * Meta ограничивает текст
     * сообщения 1000 байтами.
     */
    if (
      Buffer.byteLength(
        text,
        "utf8"
      ) > 1000
    ) {

      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(
          "Message is longer than 1000 bytes."
        )
      );
    }


    try {

      const response =
        await axios.post(
          `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/me/messages`,

          {
            recipient: {
              id: recipientId,
            },

            message: {
              text: text,
            },
          },

          {
            headers: {
              Authorization:
                `Bearer ${instagramAccessToken}`,

              "Content-Type":
                "application/json",

              Accept:
                "application/json",
            },

            timeout: 15000,
          }
        );


      console.log(
        "Instagram message sent",
        {
          recipientId:
            recipientId,

          messageId:
            response.data?.message_id ||
            null,
        }
      );


      sent_messages.unshift({
        recipientId:
          recipientId,

        text:
          text,

        timestamp:
          Date.now(),

        messageId:
          response.data?.message_id ||
          "",
      });


      if (
        sent_messages.length > 30
      ) {
        sent_messages =
          sent_messages.slice(0, 30);
      }


      return res.redirect(
        "/instagram-messages?sent=1"
      );

    } catch (error) {

      console.log(
        "Instagram message send failed"
      );


      let message =
        error.message ||
        "Instagram message could not be sent.";


      if (error.response) {

        console.log(
          JSON.stringify(
            error.response.data,
            null,
            2
          )
        );


        message =
          error.response.data
            ?.error?.message ||
          message;
      }


      return res.redirect(
        "/instagram-messages?error=" +
        encodeURIComponent(message)
      );
    }
  }
);
/**
 * ======================================================
 * 404
 * ======================================================
 */

app.use(
  function (req, res) {

    return res
      .status(404)
      .send(`

        <h2>
          Page not found
        </h2>

        <p>

          <a href="/instagram-admin">

            Open Enzhi Crew Automation

          </a>

        </p>
      `);
  }
);


/**
 * ======================================================
 * LOG UNHANDLED PROMISE ERRORS
 * ======================================================
 */

process.on(
  "unhandledRejection",

  function (reason) {

    console.error(
      "Unhandled promise rejection:",
      reason
    );
  }
);


/**
 * ======================================================
 * START SERVER
 * ======================================================
 */

app.listen(
  PORT,

  function () {

    console.log(
      `Server started on port ${PORT}`
    );
  }
);
