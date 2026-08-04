/**
 * Graph API Webhooks Sample
 * Instagram -> Heroku -> Make
 */

const express = require("express");
const bodyParser = require("body-parser");
const xhub = require("express-x-hub");
const axios = require("axios");

const app = express();

app.set("port", process.env.PORT || 5000);

app.use(
  xhub({
    algorithm: "sha1",
    secret: process.env.APP_SECRET,
  })
);

app.use(bodyParser.json());

const VERIFY_TOKEN = process.env.TOKEN || "token";

const MAKE_WEBHOOK = process.env.MAKE_WEBHOOK_URL;

const INSTAGRAM_ACCESS_TOKEN =
  process.env.INSTAGRAM_ACCESS_TOKEN;

const INSTAGRAM_API_VERSION =
  process.env.INSTAGRAM_API_VERSION || "v26.0";

let received_updates = [];

app.get("/", function (req, res) {
  res.redirect("/instagram-admin");
});

/**function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Instagram administration page
 */

app.get("/instagram-admin", async function (req, res) {
  res.set("Cache-Control", "no-store");

  let account = null;
  let errorMessage = null;

  if (!INSTAGRAM_ACCESS_TOKEN) {
    errorMessage =
      "Переменная INSTAGRAM_ACCESS_TOKEN не задана в Heroku.";
  } else {
    try {
      const response = await axios.get(
        `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/me`,
        {
          params: {
            fields: "user_id,username",
          },
          headers: {
            Authorization: `Bearer ${INSTAGRAM_ACCESS_TOKEN}`,
            Accept: "application/json",
          },
          timeout: 10000,
        }
      );

      account = {
        username: response.data.username,
        userId:
          response.data.user_id ||
          response.data.id,
      };
    } catch (error) {
      console.log("Instagram profile request failed");

      if (error.response) {
        console.log(
          JSON.stringify(error.response.data, null, 2)
        );

        errorMessage =
          error.response.data?.error?.message ||
          `Instagram API returned HTTP ${error.response.status}`;
      } else {
        console.log(error.message);
        errorMessage = error.message;
      }
    }
  }

  const accountBlock = account
    ? `
      <div class="account-card">
        <div class="connection-heading">
          <span class="status-dot"></span>
          <strong>Connected account</strong>
        </div>

        <div class="username">
          @${escapeHtml(account.username)}
        </div>

        <div class="data-row">
          <span>Account ID</span>
          <strong>${escapeHtml(account.userId)}</strong>
        </div>

        <div class="data-row">
          <span>Status</span>
          <strong class="connected">Connected</strong>
        </div>
      </div>
    `
    : `
      <div class="error-card">
        <strong>Instagram account is not connected</strong>
        <p>${escapeHtml(errorMessage)}</p>
      </div>
    `;

  const buttonText = account
    ? "Reconnect Instagram Account"
    : "Connect Instagram Account";

  res.status(account ? 200 : 500).send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1.0"
        >

        <title>Enzhi Crew Automation</title>

        <style>
          * {
            box-sizing: border-box;
          }

          body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background: #f5f6f8;
            color: #182230;
            font-family:
              Arial,
              Helvetica,
              sans-serif;
          }

          .container {
            width: 100%;
            max-width: 620px;
            padding: 40px;
            background: #ffffff;
            border-radius: 18px;
            box-shadow:
              0 16px 45px rgba(0, 0, 0, 0.09);
          }

          h1 {
            margin: 0 0 10px;
            font-size: 31px;
          }

          .description {
            margin: 0 0 26px;
            color: #667085;
            line-height: 1.55;
          }

          .connect-button {
            display: inline-block;
            margin-bottom: 28px;
            padding: 14px 22px;
            border-radius: 10px;
            background: #0866ff;
            color: #ffffff;
            font-weight: 700;
            text-decoration: none;
          }

          .connect-button:hover {
            background: #0759dc;
          }

          .account-card,
          .error-card {
            padding: 24px;
            border: 1px solid #dfe3e8;
            border-radius: 14px;
          }

          .connection-heading {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 18px;
          }

          .status-dot {
            width: 11px;
            height: 11px;
            border-radius: 50%;
            background: #12b76a;
          }

          .username {
            margin-bottom: 22px;
            font-size: 26px;
            font-weight: 700;
          }

          .data-row {
            display: flex;
            justify-content: space-between;
            gap: 20px;
            padding: 13px 0;
            border-top: 1px solid #eeeeee;
          }

          .data-row span {
            color: #667085;
          }

          .connected {
            color: #079455;
          }

          .error-card {
            background: #fff5f5;
            border-color: #f4b4b4;
          }

          .error-card p {
            margin-bottom: 0;
            overflow-wrap: anywhere;
          }

          .notice {
            margin-top: 20px;
            color: #667085;
            font-size: 13px;
            line-height: 1.5;
          }
        </style>
      </head>

      <body>
        <main class="container">
          <h1>Enzhi Crew Automation</h1>

          <p class="description">
            Connect and manage an Instagram professional account.
          </p>

          <a
            class="connect-button"
            href="/auth/instagram"
          >
            ${buttonText}
          </a>

          ${accountBlock}

          <p class="notice">
            Instagram profile information is used only
            to identify the connected professional account.
          </p>
        </main>
      </body>
    </html>
  `);
});

/**
 * Temporary route.
 * Full Instagram OAuth will be added next.
 */

app.get("/auth/instagram", function (req, res) {
  res.status(501).send(`
    <h2>Instagram authorization is not configured yet</h2>
    <p>
      The account page is working.
      OAuth will be connected in the next step.
    </p>
    <p>
      <a href="/instagram-admin">
        Return to Enzhi Crew Automation
      </a>
    </p>
  `);
});
 * Webhook verification
 */

app.get(["/facebook", "/instagram", "/threads"], function (req, res) {
  if (
    req.query["hub.mode"] === "subscribe" &&
    req.query["hub.verify_token"] === VERIFY_TOKEN
  ) {
    console.log("Webhook verified");
    return res.status(200).send(req.query["hub.challenge"]);
  }

  res.sendStatus(403);
});

/**
 * Facebook
 */

app.post("/facebook", function (req, res) {
  console.log("Facebook request body:");
  console.log(JSON.stringify(req.body, null, 2));

  if (!req.isXHubValid()) {
    console.log("Invalid X-Hub Signature");
    return res.sendStatus(401);
  }

  received_updates.unshift(req.body);

  res.sendStatus(200);
});

/**
 * Instagram
 */

app.post("/instagram", async function (req, res) {

  console.log("=======================================");
  console.log("Instagram Webhook received");
  console.log(JSON.stringify(req.body, null, 2));

  if (!req.isXHubValid()) {
    console.log("Invalid X-Hub Signature");
    return res.sendStatus(401);
  }

  received_updates.unshift(req.body);

  try {

    await axios.post(
      MAKE_WEBHOOK,
      req.body,
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

    console.log("Successfully sent to Make");

  } catch (err) {

    console.log("Error sending to Make");

    if (err.response) {
      console.log(err.response.data);
    } else {
      console.log(err.message);
    }

  }

  res.sendStatus(200);

});

/**
 * Threads
 */

app.post("/threads", function (req, res) {

  console.log("Threads request body:");
  console.log(JSON.stringify(req.body, null, 2));

  received_updates.unshift(req.body);

  res.sendStatus(200);

});

app.listen(app.get("port"), function () {
  console.log("Server started on port " + app.get("port"));
});
