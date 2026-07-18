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

const MAKE_WEBHOOK =
  "https://hook.eu1.make.com/r5b2fu92lxmvbrb5238hucahaotp2uot";

let received_updates = [];

app.get("/", function (req, res) {
  res.send(
    "<pre>" + JSON.stringify(received_updates, null, 2) + "</pre>"
  );
});

/**
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
