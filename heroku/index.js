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
