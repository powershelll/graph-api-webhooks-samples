/**
 * Enzhi Crew Automation
 * Instagram -> Heroku -> Make
 * VK -> Heroku -> Fixie -> VK API
 */

const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 5000;

/**
 * ======================================================
 * COMMON / INSTAGRAM CONFIG
 * ======================================================
 */

const APP_SECRET = process.env.APP_SECRET || null;

const VERIFY_TOKEN =
  process.env.WEBHOOK_VERIFY_TOKEN ||
  process.env.TOKEN ||
  null;

const MAKE_WEBHOOK =
  process.env.MAKE_WEBHOOK_URL ||
  null;

let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN ||
  null;

const INSTAGRAM_APP_ID =
  process.env.INSTAGRAM_APP_ID ||
  null;

const INSTAGRAM_APP_SECRET =
  process.env.INSTAGRAM_APP_SECRET ||
  null;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI ||
  null;

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  process.env.APP_SECRET ||
  null;

const INSTAGRAM_API_VERSION =
  process.env.INSTAGRAM_API_VERSION ||
  "v26.0";


/**
 * ======================================================
 * VK CONFIG — CLASSIC VK API OAUTH
 * ======================================================
 *
 * Heroku Config Vars:
 *
 * VK_APP_ID
 * VK_CLIENT_SECRET
 * VK_REDIRECT_URI=https://auth.enzhicrew.ru/vk/callback
 * VK_GROUP_ID=197890975
 * VK_FIXIE_URL=http://fixie:PASSWORD@ONE_STATIC_IP:80
 * VK_POST_SECRET=...
 *
 * После первой успешной авторизации:
 *
 * VK_ACCESS_TOKEN=...
 */

const VK_APP_ID =
  process.env.VK_APP_ID ||
  null;

const VK_CLIENT_SECRET =
  process.env.VK_CLIENT_SECRET ||
  null;

const VK_GROUP_ID =
  String(
    process.env.VK_GROUP_ID ||
    "197890975"
  ).replace(/^-/, "");

const VK_REDIRECT_URI =
  process.env.VK_REDIRECT_URI ||
  "https://auth.enzhicrew.ru/vk/callback";

const VK_API_VERSION =
  "5.199";

const VK_POST_SECRET =
  process.env.VK_POST_SECRET ||
  null;

const VK_STATE_SECRET =
  process.env.VK_OAUTH_STATE_SECRET ||
  VK_CLIENT_SECRET ||
  OAUTH_STATE_SECRET ||
  null;

let vkAccessToken =
  process.env.VK_ACCESS_TOKEN ||
  null;


/**
 * ======================================================
 * IN-MEMORY STORAGE
 * ======================================================
 */

let receivedUpdates = [];

let sentMessages = [];


/**
 * ======================================================
 * BODY PARSER
 * ======================================================
 */

app.use(
  bodyParser.json({
    verify: function (
      req,
      res,
      buf
    ) {

      req.rawBody =
        Buffer.from(buf);
    },
  })
);


app.use(
  bodyParser.urlencoded({
    extended: false,
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


function rememberUpdate(body) {

  receivedUpdates.unshift(
    body
  );


  if (
    receivedUpdates.length >
    100
  ) {

    receivedUpdates =
      receivedUpdates.slice(
        0,
        100
      );
  }


  console.log(
    "Webhook stored in memory",
    {
      totalUpdates:
        receivedUpdates.length,
    }
  );
}


/**
 * ======================================================
 * INSTAGRAM OAUTH STATE
 * ======================================================
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


function validateOAuthState(state) {

  if (
    !state ||
    !OAUTH_STATE_SECRET
  ) {

    return false;
  }


  const parts =
    String(state).split(".");


  if (
    parts.length !== 3
  ) {

    return false;
  }


  const timestamp =
    Number(parts[0]);


  if (
    !Number.isFinite(
      timestamp
    )
  ) {

    return false;
  }


  const stateAge =
    Date.now() -
    timestamp;


  if (
    stateAge < 0 ||
    stateAge >
      10 * 60 * 1000
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

    algorithm =
      "sha256";

    prefix =
      "sha256=";

  } else if (signature1) {

    receivedSignature =
      String(signature1);

    algorithm =
      "sha1";

    prefix =
      "sha1=";

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
 * ======================================================
 * INSTAGRAM MESSAGE PARSER
 * ======================================================
 */

function getRecentInstagramMessages() {

  const messages = [];

  const seen =
    new Set();


  function addMessage(data) {

    if (!data) {

      return;
    }


    const text =
      typeof data.text ===
      "string"

        ? data.text.trim()

        : "";


    if (!text) {

      return;
    }


    const messageId =
      String(
        data.messageId ||
        ""
      );


    if (
      messageId &&
      seen.has(
        messageId
      )
    ) {

      return;
    }


    if (messageId) {

      seen.add(
        messageId
      );
    }


    let timestamp =
      Number(
        data.timestamp ||
        0
      );


    if (
      timestamp > 0 &&
      timestamp <
        100000000000
    ) {

      timestamp *=
        1000;
    }


    messages.push({

      senderId:
        String(
          data.senderId ||
          ""
        ),

      recipientId:
        String(
          data.recipientId ||
          ""
        ),

      text:
        text,

      timestamp:
        timestamp,

      messageId:
        messageId,
    });
  }


  for (
    const update
    of receivedUpdates
  ) {

    if (
      !update ||
      update.object !==
        "instagram"
    ) {

      continue;
    }


    const entries =
      Array.isArray(
        update.entry
      )

        ? update.entry

        : [];


    for (
      const entry
      of entries
    ) {

      const messagingEvents =
        Array.isArray(
          entry.messaging
        )

          ? entry.messaging

          : [];


      for (
        const event
        of messagingEvents
      ) {

        if (
          !event.message ||
          event.message.is_echo
        ) {

          continue;
        }


        addMessage({

          senderId:
            event.sender?.id,

          recipientId:
            event.recipient?.id,

          text:
            event.message?.text,

          timestamp:
            event.timestamp,

          messageId:
            event.message?.mid,
        });
      }


      const changes =
        Array.isArray(
          entry.changes
        )

          ? entry.changes

          : [];


      for (
        const change
        of changes
      ) {

        if (
          change.field !==
          "messages"
        ) {

          continue;
        }


        const value =
          change.value ||
          {};


        if (!value.message) {

          continue;
        }


        addMessage({

          senderId:
            value.sender?.id,

          recipientId:
            value.recipient?.id,

          text:
            value.message?.text,

          timestamp:
            value.timestamp,

          messageId:
            value.message?.mid,
        });
      }
    }
  }


  messages.sort(
    (
      a,
      b
    ) =>
      b.timestamp -
      a.timestamp
  );


  return messages.slice(
    0,
    30
  );
}


/**
 * ======================================================
 * VK FIXIE PROXY
 * ======================================================
 */

function getVkProxy() {

  const proxyUrl =
    process.env.VK_FIXIE_URL;


  if (!proxyUrl) {

    throw new Error(
      "VK_FIXIE_URL is not configured"
    );
  }


  const parsed =
    new URL(
      proxyUrl
    );


  return {

    protocol:
      parsed.protocol.replace(
        ":",
        ""
      ),

    host:
      parsed.hostname,

    port:
      Number(
        parsed.port ||
        80
      ),

    auth: {

      username:
        decodeURIComponent(
          parsed.username
        ),

      password:
        decodeURIComponent(
          parsed.password
        ),
    },
  };
}


/**
 * ======================================================
 * VK API REQUEST
 * ======================================================
 */

async function vkApi(
  method,
  params = {}
) {

  if (!vkAccessToken) {

    throw new Error(
      "VK_ACCESS_TOKEN is not configured"
    );
  }


  const form =
    new URLSearchParams();


  for (
    const [
      key,
      value
    ]
    of Object.entries(
      params
    )
  ) {

    if (
      value !==
        undefined &&
      value !==
        null
    ) {

      form.append(
        key,
        String(value)
      );
    }
  }


  form.append(
    "access_token",
    vkAccessToken
  );


  form.append(
    "v",
    VK_API_VERSION
  );


  const response =
    await axios.post(

      `https://api.vk.com/method/${method}`,

      form.toString(),

      {
        headers: {

          "Content-Type":
            "application/x-www-form-urlencoded",
        },

        proxy:
          getVkProxy(),

        timeout:
          30000,
      }
    );


  if (
    response.data?.error
  ) {

    const vkError =
      response.data.error;


    const error =
      new Error(
        `VK ${method}: ${vkError.error_msg}`
      );


    error.vkError =
      vkError;


    throw error;
  }


  return response
    .data
    .response;
}


function sendVkError(
  res,
  error
) {

  console.error(
    "VK ERROR:",
    error.response?.data ||
    error.vkError ||
    error.message
  );


  return res
    .status(500)
    .json({

      success:
        false,

      error:
        error.message,

      vk_error:
        error.vkError ||
        error.response?.data ||
        null,
    });
}


/**
 * ======================================================
 * VK OAUTH STATE
 * ======================================================
 */

function createVkOAuthState() {

  if (!VK_STATE_SECRET) {

    throw new Error(
      "VK OAuth state secret is not configured"
    );
  }


  const timestamp =
    Date.now()
      .toString();


  const nonce =
    crypto
      .randomBytes(24)
      .toString("hex");


  const payload =
    `${timestamp}.${nonce}`;


  const signature =
    crypto
      .createHmac(
        "sha256",
        VK_STATE_SECRET
      )
      .update(payload)
      .digest("hex");


  return (
    `${payload}.${signature}`
  );
}


function validateVkOAuthState(
  state
) {

  if (
    !state ||
    !VK_STATE_SECRET
  ) {

    return false;
  }


  const parts =
    String(state)
      .split(".");


  if (
    parts.length !==
    3
  ) {

    return false;
  }


  const [
    timestamp,
    nonce,
    signature
  ] =
    parts;


  const timestampNumber =
    Number(
      timestamp
    );


  if (
    !Number.isFinite(
      timestampNumber
    )
  ) {

    return false;
  }


  const age =
    Date.now() -
    timestampNumber;


  if (
    age < 0 ||
    age >
      10 * 60 * 1000
  ) {

    return false;
  }


  const payload =
    `${timestamp}.${nonce}`;


  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        VK_STATE_SECRET
      )
      .update(payload)
      .digest("hex");


  try {

    const receivedBuffer =
      Buffer.from(
        signature,
        "hex"
      );


    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "hex"
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


  } catch (_) {

    return false;
  }
}


/**
 * ======================================================
 * VK OAUTH START
 * ======================================================
 *
 * Открываем:
 *
 * https://auth.enzhicrew.ru/vk/auth
 */

app.get(
  "/vk/auth",

  function (
    req,
    res
  ) {

    const missing =
      [];


    if (!VK_APP_ID) {

      missing.push(
        "VK_APP_ID"
      );
    }


    if (!VK_CLIENT_SECRET) {

      missing.push(
        "VK_CLIENT_SECRET"
      );
    }


    if (!VK_REDIRECT_URI) {

      missing.push(
        "VK_REDIRECT_URI"
      );
    }


    if (
      !process.env
        .VK_FIXIE_URL
    ) {

      missing.push(
        "VK_FIXIE_URL"
      );
    }


    if (!VK_STATE_SECRET) {

      missing.push(
        "VK_OAUTH_STATE_SECRET"
      );
    }


    if (
      missing.length >
      0
    ) {

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "VK OAuth is not configured",

          missing:
            missing,
        });
    }


    const state =
      createVkOAuthState();


    const params =
      new URLSearchParams({

        client_id:
          String(
            VK_APP_ID
          ),

        display:
          "page",

        redirect_uri:
          VK_REDIRECT_URI,

        scope:
          "photos,wall,groups,offline",

        response_type:
          "code",

        v:
          VK_API_VERSION,

        state:
          state,
      });


    return res.redirect(

      `https://oauth.vk.com/authorize?${params.toString()}`
    );
  }
);


/**
 * ======================================================
 * VK OAUTH CALLBACK
 * ======================================================
 */

app.get(
  "/vk/callback",

  async function (
    req,
    res
  ) {

    const code =
      req.query.code;


    const state =
      req.query.state;


    if (
      req.query.error
    ) {

      return res
        .status(400)
        .send(

          escapeHtml(

            req.query
              .error_description ||

            req.query
              .error
          )
        );
    }


    if (!code) {

      return res
        .status(400)
        .send(
          "VK authorization code is missing"
        );
    }


    if (
      !validateVkOAuthState(
        state
      )
    ) {

      return res
        .status(403)
        .send(
          "Invalid VK OAuth state"
        );
    }


    try {

      const tokenResponse =
        await axios.get(

          "https://oauth.vk.com/access_token",

          {
            params: {

              client_id:
                VK_APP_ID,

              client_secret:
                VK_CLIENT_SECRET,

              redirect_uri:
                VK_REDIRECT_URI,

              code:
                String(
                  code
                ),
            },

            proxy:
              getVkProxy(),

            timeout:
              30000,
          }
        );


      const data =
        tokenResponse.data;


      if (
        data?.error
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            vk:
              data,
          });
      }


      if (
        !data?.access_token
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            error:
              "VK did not return access_token",

            response:
              data,
          });
      }


      vkAccessToken =
        data.access_token;


      console.log(
        "VK CLASSIC USER TOKEN RECEIVED",
        {
          user_id:
            data.user_id,

          expires_in:
            data.expires_in,
        }
      );


      /**
       * Проверяем токен сразу.
       */

      try {

        await vkApi(

          "photos.getWallUploadServer",

          {
            group_id:
              VK_GROUP_ID,
          }
        );


      } catch (
        testError
      ) {

        return res
          .status(500)
          .json({

            success:
              false,

            message:
              "User Token получен, но photos.getWallUploadServer не работает",

            user_id:
              data.user_id,

            vk_error:
              testError.vkError ||
              testError.message,
          });
      }


      return res
        .status(200)
        .send(`
<!DOCTYPE html>

<html lang="ru">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>
    VK подключён
  </title>

  <style>

    body {
      font-family:
        Arial,
        sans-serif;

      background:
        #f5f5f5;

      padding:
        30px 15px;

      color:
        #182230;
    }

    .card {
      max-width:
        700px;

      margin:
        auto;

      background:
        #ffffff;

      padding:
        30px;

      border-radius:
        16px;

      box-shadow:
        0 5px 20px
        rgba(0,0,0,.08);
    }

    .success {
      color:
        #079455;

      font-weight:
        700;
    }

    textarea {
      width:
        100%;

      min-height:
        160px;

      padding:
        12px;

      box-sizing:
        border-box;

      margin-top:
        10px;
    }

    .warning {
      color:
        #667085;

      margin-top:
        20px;
    }

  </style>

</head>


<body>

  <div class="card">

    <h1>
      VK успешно подключён
    </h1>


    <p class="success">
      photos.getWallUploadServer работает.
    </p>


    <p>

      User ID:

      <strong>
        ${escapeHtml(
          data.user_id
        )}
      </strong>

    </p>


    <p>

      Скопируй токен ниже
      и сохрани в Heroku
      Config Vars как

      <strong>
        VK_ACCESS_TOKEN
      </strong>.

    </p>


    <textarea readonly>${escapeHtml(
      data.access_token
    )}</textarea>


    <p class="warning">

      Никому не отправляй
      этот токен.

    </p>

  </div>

</body>

</html>
      `);


    } catch (error) {

      console.error(

        "VK OAuth callback failed:",

        error.response?.data ||
        error.message
      );


      return res
        .status(500)
        .json({

          success:
            false,

          error:
            error.message,

          vk:
            error.response?.data ||
            null,
        });
    }
  }
);


/**
 * ======================================================
 * VK STATUS
 * ======================================================
 */

app.get(
  "/vk/status",

  async function (
    req,
    res
  ) {

    if (!vkAccessToken) {

      return res.json({

        success:
          false,

        connected:
          false,

        message:
          "VK_ACCESS_TOKEN is missing",
      });
    }


    try {

      const uploadServer =
        await vkApi(

          "photos.getWallUploadServer",

          {
            group_id:
              VK_GROUP_ID,
          }
        );


      return res.json({

        success:
          true,

        connected:
          true,

        group_id:
          VK_GROUP_ID,

        upload_server_available:
          Boolean(
            uploadServer
              ?.upload_url
          ),
      });


    } catch (error) {

      return sendVkError(
        res,
        error
      );
    }
  }
);


/**
 * ======================================================
 * VK POST WITH PHOTO
 * ======================================================
 *
 * POST:
 *
 * https://auth.enzhicrew.ru/vk/post
 *
 * Header:
 *
 * X-VK-Post-Secret
 *
 * JSON:
 *
 * {
 *   "image_url": "https://...",
 *   "caption": "Text"
 * }
 */

app.post(
  "/vk/post",

  async function (
    req,
    res
  ) {

    const receivedSecret =
      req.get(
        "X-VK-Post-Secret"
      );


    if (
      !VK_POST_SECRET ||
      receivedSecret !==
        VK_POST_SECRET
    ) {

      return res
        .status(401)
        .json({

          success:
            false,

          error:
            "Unauthorized",
        });
    }


    const {
      image_url,
      caption,
    } =
      req.body ||
      {};


    if (!image_url) {

      return res
        .status(400)
        .json({

          success:
            false,

          error:
            "image_url is required",
        });
    }


    if (!vkAccessToken) {

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "VK_ACCESS_TOKEN is missing. Open /vk/auth first.",
        });
    }


    try {

      /**
       * STEP 1
       *
       * Получаем upload_url.
       */

      const uploadServer =
        await vkApi(

          "photos.getWallUploadServer",

          {
            group_id:
              VK_GROUP_ID,
          }
        );


      if (
        !uploadServer
          ?.upload_url
      ) {

        throw new Error(
          "VK did not return upload_url"
        );
      }


      /**
       * STEP 2
       *
       * Скачиваем картинку.
       */

      const imageResponse =
        await axios.get(

          String(
            image_url
          ),

          {
            responseType:
              "arraybuffer",

            timeout:
              30000,

            maxContentLength:
              20 *
              1024 *
              1024,

            maxBodyLength:
              20 *
              1024 *
              1024,
          }
        );


      const imageBuffer =
        Buffer.from(
          imageResponse.data
        );


      const contentType =
        String(

          imageResponse
            .headers[
              "content-type"
            ] ||

          "image/jpeg"
        )
          .split(";")[0]
          .trim();


      if (
        !contentType
          .startsWith(
            "image/"
          )
      ) {

        throw new Error(
          `image_url returned ${contentType}, not an image`
        );
      }


      let extension =
        "jpg";


      if (
        contentType ===
        "image/png"
      ) {

        extension =
          "png";

      } else if (
        contentType ===
        "image/webp"
      ) {

        extension =
          "webp";

      } else if (
        contentType ===
        "image/gif"
      ) {

        extension =
          "gif";
      }


      /**
       * STEP 3
       *
       * Формируем multipart.
       */

      const uploadForm =
        new FormData();


      uploadForm.append(

        "photo",

        new Blob(
          [
            imageBuffer
          ],
          {
            type:
              contentType,
          }
        ),

        `photo.${extension}`
      );


      /**
       * STEP 4
       *
       * Загружаем фото на VK.
       *
       * Через тот же Fixie IP.
       */

      const uploaded =
        await axios.post(

          uploadServer
            .upload_url,

          uploadForm,

          {
            proxy:
              getVkProxy(),

            timeout:
              60000,

            maxBodyLength:
              Infinity,

            maxContentLength:
              Infinity,
          }
        );


      let uploadData =
        uploaded.data;


      if (
        typeof uploadData ===
        "string"
      ) {

        uploadData =
          JSON.parse(
            uploadData
          );
      }


      if (
        !uploadData?.server ||
        !uploadData?.photo ||
        !uploadData?.hash
      ) {

        console.error(
          "VK upload response:",
          uploadData
        );


        throw new Error(
          "Invalid response from VK upload server"
        );
      }


      /**
       * STEP 5
       *
       * Сохраняем фото.
       */

      const savedPhotos =
        await vkApi(

          "photos.saveWallPhoto",

          {
            group_id:
              VK_GROUP_ID,

            server:
              uploadData.server,

            photo:
              typeof uploadData.photo ===
              "string"

                ? uploadData.photo

                : JSON.stringify(
                    uploadData.photo
                  ),

            hash:
              uploadData.hash,
          }
        );


      if (
        !Array.isArray(
          savedPhotos
        ) ||
        !savedPhotos[0]
      ) {

        throw new Error(
          "VK did not save photo"
        );
      }


      const photo =
        savedPhotos[0];


      const attachment =
        `photo${photo.owner_id}_${photo.id}`;


      /**
       * STEP 6
       *
       * Публикуем пост.
       */

      const post =
        await vkApi(

          "wall.post",

          {
            owner_id:
              `-${VK_GROUP_ID}`,

            from_group:
              1,

            message:
              String(
                caption ||
                ""
              ),

            attachments:
              attachment,
          }
        );


      return res
        .status(200)
        .json({

          success:
            true,

          post_id:
            post.post_id,

          attachment:
            attachment,

          group_id:
            VK_GROUP_ID,
        });


    } catch (error) {

      return sendVkError(
        res,
        error
      );
    }
  }
);


/**
 * ======================================================
 * MAIN PAGE
 * ======================================================
 */

app.get(
  "/",

  function (
    req,
    res
  ) {

    return res.redirect(
      "/instagram-admin"
    );
  }
);


/**
 * ======================================================
 * HEALTH
 * ======================================================
 */

app.get(
  "/health",

  function (
    req,
    res
  ) {

    return res
      .status(200)
      .json({

        status:
          "ok",

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

  async function (
    req,
    res
  ) {

    res.set(
      "Cache-Control",
      "no-store"
    );


    let account =
      null;


    let errorMessage =
      null;


    if (
      !instagramAccessToken
    ) {

      errorMessage =
        "Instagram access token is not configured.";

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

              timeout:
                10000,
            }
          );


        account = {

          username:
            response
              .data
              .username ||
            "unknown",

          userId:
            response
              .data
              .user_id ||

            response
              .data
              .id ||

            "unknown",
        };


      } catch (error) {

        console.error(
          "Instagram profile request failed"
        );


        if (
          error.response
        ) {

          console.error(

            JSON.stringify(

              error.response
                .data,

              null,
              2
            )
          );


          errorMessage =
            error.response
              .data
              ?.error
              ?.message ||

            `Instagram API returned HTTP ${error.response.status}`;


        } else {

          errorMessage =
            error.message ||

            "Instagram API request failed.";
        }
      }
    }


    const accountBlock =
      account

        ? `

          <div class="card">

            <div class="connected">
              ● Connected account
            </div>

            <h2>
              @${escapeHtml(
                account.username
              )}
            </h2>

            <p>

              Account ID:

              <strong>
                ${escapeHtml(
                  account.userId
                )}
              </strong>

            </p>

          </div>

        `

        : `

          <div class="card error">

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
    content="width=device-width, initial-scale=1.0"
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

      margin:
        0;

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
        rgba(0,0,0,.09);
    }

    h1 {
      margin:
        0 0 10px;
    }

    .description {
      color:
        #667085;
    }

    .button {

      display:
        inline-block;

      margin:
        15px 0 25px;

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

    .card {

      padding:
        24px;

      border:
        1px solid #dfe3e8;

      border-radius:
        14px;
    }

    .error {

      background:
        #fff5f5;

      border-color:
        #f4b4b4;
    }

    .connected {

      color:
        #079455;

      font-weight:
        700;
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
      Instagram professional account.

    </p>


    <a
      class="button"
      href="/auth/instagram"
    >

      ${buttonText}

    </a>


    ${accountBlock}


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

  function (
    req,
    res
  ) {

    const missingVariables =
      [];


    if (
      !INSTAGRAM_APP_ID
    ) {

      missingVariables.push(
        "INSTAGRAM_APP_ID"
      );
    }


    if (
      !INSTAGRAM_APP_SECRET
    ) {

      missingVariables.push(
        "INSTAGRAM_APP_SECRET"
      );
    }


    if (
      !INSTAGRAM_REDIRECT_URI
    ) {

      missingVariables.push(
        "INSTAGRAM_REDIRECT_URI"
      );
    }


    if (
      !OAUTH_STATE_SECRET
    ) {

      missingVariables.push(
        "OAUTH_STATE_SECRET"
      );
    }


    if (
      missingVariables.length >
      0
    ) {

      return res
        .status(500)
        .send(`

          <h2>
            Instagram OAuth
            is not configured
          </h2>

          <pre>
${escapeHtml(
  missingVariables.join(
    "\n"
  )
)}
          </pre>

        `);
    }


    const state =
      createOAuthState();


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


    return res.redirect(

      "https://www.instagram.com/oauth/authorize?" +
      parameters.toString()
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

  async function (
    req,
    res
  ) {

    const authorizationCode =
      req.query.code;


    const returnedState =
      req.query.state;


    console.log(
      "Instagram OAuth callback received",
      {

        hasCode:
          Boolean(
            authorizationCode
          ),

        hasState:
          Boolean(
            returnedState
          ),

        error:
          req.query.error ||
          null,
      }
    );


    if (
      req.query.error
    ) {

      return res
        .status(400)
        .send(

          escapeHtml(

            req.query
              .error_description ||

            req.query
              .error
          )
        );
    }


    if (
      !authorizationCode
    ) {

      return res
        .status(400)
        .send(
          "Authorization code is missing"
        );
    }


    if (
      !validateOAuthState(
        returnedState
      )
    ) {

      return res
        .status(403)
        .send(
          "Invalid OAuth state"
        );
    }


    try {

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

        String(
          authorizationCode
        )
      );


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
          "Instagram did not return access token"
        );
      }


      let finalToken =
        shortToken;


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


      } catch (error) {

        console.error(
          "Long-lived token exchange failed"
        );
      }


      instagramAccessToken =
        finalToken;


      return res.redirect(
        "/instagram-admin?connected=1"
      );


    } catch (error) {

      console.error(
        "Instagram OAuth callback failed"
      );


      let message =
        error.message;


      if (
        error.response
      ) {

        message =

          error.response
            .data
            ?.error_message ||

          error.response
            .data
            ?.error
            ?.message ||

          message;
      }


      return res
        .status(500)
        .send(
          escapeHtml(
            message
          )
        );
    }
  }
);


/**
 * ======================================================
 * INSTAGRAM WEBHOOK VERIFICATION
 * ======================================================
 */

app.get(
  "/instagram",

  function (
    req,
    res
  ) {

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
      mode ===
        "subscribe" &&

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
        .type(
          "text/plain"
        )
        .send(
          String(
            challenge
          )
        );
    }


    return res
      .status(403)
      .send(
        "Verification failed"
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

  async function (
    req,
    res
  ) {

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


    if (
      !verifyMetaSignature(
        req
      )
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


    res.sendStatus(
      200
    );


    if (!MAKE_WEBHOOK) {

      console.log(
        "MAKE_WEBHOOK_URL is not configured"
      );

      return;
    }


    try {

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
        "Error sending to Make",
        error.message
      );
    }
  }
);


/**
 * ======================================================
 * ENABLE MESSAGE WEBHOOK
 * ======================================================
 */

app.post(

  "/instagram-messages/subscribe",

  async function (
    req,
    res
  ) {

    if (
      !instagramAccessToken
    ) {

      return res.redirect(

        "/instagram-messages?error=" +

        encodeURIComponent(
          "Instagram access token is missing."
        )
      );
    }


    try {

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
          }
        );


      const instagramUserId =

        profileResponse
          .data
          .user_id ||

        profileResponse
          .data
          .id;


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

      let message =
        error.message;


      if (
        error.response
      ) {

        message =

          error.response
            .data
            ?.error
            ?.message ||

          message;
      }


      return res.redirect(

        "/instagram-messages?error=" +

        encodeURIComponent(
          message
        )
      );
    }
  }
);


/**
 * ======================================================
 * CLEAR DEMO MESSAGES
 * ======================================================
 */

app.post(

  "/instagram-messages/clear",

  function (
    req,
    res
  ) {

    receivedUpdates =
      [];


    sentMessages =
      [];


    console.log(
      "Instagram demo messages cleared"
    );


    return res.redirect(
      "/instagram-messages?cleared=1"
    );
  }
);


/**
 * ======================================================
 * SEND MESSAGE
 * ======================================================
 */

app.post(

  "/instagram-messages/send",

  async function (
    req,
    res
  ) {

    const recipientId =
      String(

        req.body
          .recipientId ||

        ""
      ).trim();


    const text =
      String(

        req.body
          .text ||

        ""
      ).trim();


    if (
      !instagramAccessToken
    ) {

      return res.redirect(

        "/instagram-messages?error=" +

        encodeURIComponent(
          "Instagram access token is missing."
        )
      );
    }


    if (
      !recipientId ||
      !text
    ) {

      return res.redirect(

        "/instagram-messages?error=" +

        encodeURIComponent(
          "Recipient or message is missing."
        )
      );
    }


    try {

      const response =
        await axios.post(

          `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/me/messages`,

          {
            recipient: {

              id:
                recipientId,
            },

            message: {

              text:
                text,
            },
          },

          {
            headers: {

              Authorization:
                `Bearer ${instagramAccessToken}`,

              "Content-Type":
                "application/json",
            },
          }
        );


      sentMessages.unshift({

        recipientId:
          recipientId,

        text:
          text,

        messageId:

          response.data
            ?.message_id ||

          "",

        timestamp:
          Date.now(),
      });


      return res.redirect(
        "/instagram-messages?sent=1"
      );


    } catch (error) {

      let message =
        error.message;


      if (
        error.response
      ) {

        message =

          error.response
            .data
            ?.error
            ?.message ||

          message;
      }


      return res.redirect(

        "/instagram-messages?error=" +

        encodeURIComponent(
          message
        )
      );
    }
  }
);


/**
 * ======================================================
 * INSTAGRAM MESSAGES PAGE
 * ======================================================
 */

app.get(

  "/instagram-messages",

  function (
    req,
    res
  ) {

    res.set(
      "Cache-Control",
      "no-store"
    );


    const messages =
      getRecentInstagramMessages();


    const sentSuccessfully =
      req.query.sent ===
      "1";


    const subscribedSuccessfully =
      req.query.subscribed ===
      "1";


    const clearedSuccessfully =
      req.query.cleared ===
      "1";


    const errorMessage =
      req.query.error

        ? String(
            req.query.error
          )

        : null;


    const incomingHtml =

      messages.length >
      0

        ? messages

            .map(

              function (
                message
              ) {

                let time =
                  "";


                if (
                  message.timestamp
                ) {

                  try {

                    time =
                      new Date(
                        message.timestamp
                      )
                        .toLocaleString(
                          "ru-RU"
                        );


                  } catch (_) {

                    time =
                      "";
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

                              ${escapeHtml(
                                time
                              )}

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
              }
            )

            .join("")


        : `

          <div class="empty-card">

            <strong>
              No incoming messages yet
            </strong>

            <p>

              Send a Direct message
              to the connected
              Instagram account.

            </p>

          </div>

        `;


    const sentHtml =

      sentMessages.length >
      0

        ? sentMessages

            .slice(
              0,
              10
            )

            .map(

              function (
                message
              ) {

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
              }
            )

            .join("")


        : `

          <p class="muted">

            No replies sent during
            this server session.

          </p>

        `;


    return res
      .status(200)
      .send(`

<!DOCTYPE html>

<html lang="en">

<head>

  <meta charset="UTF-8">


  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >


  <title>
    Instagram Messages
  </title>


  <style>

    * {
      box-sizing:
        border-box;
    }


    body {

      margin:
        0;

      padding:
        36px;

      background:
        #f5f6f8;

      color:
        #182230;

      font-family:
        Arial,
        sans-serif;
    }


    .container {

      max-width:
        850px;

      margin:
        0 auto;
    }


    .subtitle,
    .muted,
    .time,
    .label {

      color:
        #667085;
    }


    .top-actions {

      display:
        flex;

      gap:
        12px;

      flex-wrap:
        wrap;

      margin-bottom:
        25px;
    }


    .button {

      display:
        inline-block;

      padding:
        11px 16px;

      border:
        0;

      border-radius:
        9px;

      background:
        #0866ff;

      color:
        white;

      text-decoration:
        none;

      cursor:
        pointer;

      font-weight:
        700;

      font-size:
        14px;
    }


    .secondary {

      background:
        #344054;
    }


    .danger {

      background:
        #d92d20;
    }


    .message-card,
    .empty-card,
    .sent-message {

      background:
        white;

      border:
        1px solid #e4e7ec;

      border-radius:
        14px;

      padding:
        22px;

      margin-bottom:
        18px;
    }


    .message-header {

      display:
        flex;

      justify-content:
        space-between;

      gap:
        15px;

      margin-bottom:
        20px;
    }


    .label {

      font-size:
        12px;

      margin-top:
        12px;

      margin-bottom:
        5px;
    }


    .sender {

      font-weight:
        700;
    }


    .message-text {

      padding:
        14px;

      background:
        #f9fafb;

      border-radius:
        9px;

      line-height:
        1.5;

      margin-bottom:
        20px;

      white-space:
        pre-wrap;
    }


    textarea {

      display:
        block;

      width:
        100%;

      min-height:
        90px;

      resize:
        vertical;

      margin:
        7px 0 12px;

      padding:
        12px;

      border:
        1px solid #d0d5dd;

      border-radius:
        9px;

      font:
        inherit;
    }


    .reply-button {

      padding:
        11px 18px;

      border:
        0;

      border-radius:
        9px;

      background:
        #12b76a;

      color:
        white;

      font-weight:
        700;

      cursor:
        pointer;
    }


    .success,
    .error {

      padding:
        14px;

      margin-bottom:
        18px;

      border-radius:
        10px;
    }


    .success {

      background:
        #ecfdf3;

      border:
        1px solid #abefc6;
    }


    .error {

      background:
        #fff1f0;

      border:
        1px solid #fecdca;
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
        action="/instagram-messages/clear"
        style="margin:0"
      >

        <button
          class="button danger"
          type="submit"
        >
          Clear Messages
        </button>

      </form>


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
      clearedSuccessfully

        ? `

          <div class="success">

            Messages cleared.
            Ready for demonstration.

          </div>

        `

        : ""
    }


    ${
      subscribedSuccessfully

        ? `

          <div class="success">

            Instagram account
            subscribed to
            message webhooks.

          </div>

        `

        : ""
    }


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
 * ======================================================
 * INSTAGRAM CONVERSATIONS DEBUG
 * ======================================================
 */

app.get(

  "/instagram-conversations",

  async function (
    req,
    res
  ) {

    if (
      !instagramAccessToken
    ) {

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "Instagram access token is missing.",
        });
    }


    try {

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
          }
        );


      const instagramUserId =

        profileResponse
          .data
          .user_id ||

        profileResponse
          .data
          .id;


      const conversationsResponse =
        await axios.get(

          `https://graph.instagram.com/${INSTAGRAM_API_VERSION}/${instagramUserId}/conversations`,

          {
            params: {

              platform:
                "instagram",

              fields:
                "id,updated_time",

              limit:
                20,
            },

            headers: {

              Authorization:
                `Bearer ${instagramAccessToken}`,
            },
          }
        );


      return res.json({

        success:
          true,

        account: {

          id:
            instagramUserId,

          username:

            profileResponse
              .data
              .username ||

            null,
        },

        conversations:

          conversationsResponse
            .data
            .data ||

          [],

        paging:

          conversationsResponse
            .data
            .paging ||

          null,
      });


    } catch (error) {

      return res
        .status(500)
        .json({

          success:
            false,

          error:

            error.response
              ?.data
              ?.error
              ?.message ||

            error.message,
        });
    }
  }
);


/**
 * ======================================================
 * DEBUG INSTAGRAM WEBHOOK
 * ======================================================
 */

app.get(

  "/debug-instagram",

  function (
    req,
    res
  ) {

    return res
      .status(200)
      .json({

        updatesCount:
          receivedUpdates.length,

        latestUpdate:

          receivedUpdates.length

            ? receivedUpdates[0]

            : null,

        parsedMessages:
          getRecentInstagramMessages(),
      });
  }
);


/**
 * ======================================================
 * INSTAGRAM DEAUTHORIZE
 * ======================================================
 */

app.post(

  "/instagram/deauthorize",

  function (
    req,
    res
  ) {

    console.log(
      "Instagram deauthorization received"
    );


    return res.sendStatus(
      200
    );
  }
);


/**
 * ======================================================
 * INSTAGRAM DATA DELETION
 * ======================================================
 */

app.post(

  "/instagram/data-deletion",

  function (
    req,
    res
  ) {

    const confirmationCode =
      crypto
        .randomBytes(12)
        .toString("hex");


    return res
      .status(200)
      .json({

        url:

          `https://${req.get(
            "host"
          )}/instagram/data-deletion/status?code=${confirmationCode}`,

        confirmation_code:
          confirmationCode,
      });
  }
);


app.get(

  "/instagram/data-deletion/status",

  function (
    req,
    res
  ) {

    return res
      .status(200)
      .send(`

        <h2>
          Data deletion request
        </h2>

        <p>
          Your request has been received.
        </p>

        <p>

          Confirmation code:

          ${escapeHtml(
            req.query.code ||
            ""
          )}

        </p>

      `);
  }
);


/**
 * ======================================================
 * FACEBOOK WEBHOOK
 * ======================================================
 */

app.get(

  "/facebook",

  function (
    req,
    res
  ) {

    const mode =
      req.query[
        "hub.mode"
      ];


    const token =
      req.query[
        "hub.verify_token"
      ];


    const challenge =
      req.query[
        "hub.challenge"
      ];


    if (
      mode ===
        "subscribe" &&

      VERIFY_TOKEN &&

      token ===
        VERIFY_TOKEN &&

      challenge
    ) {

      return res
        .status(200)
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


app.post(

  "/facebook",

  function (
    req,
    res
  ) {

    if (
      !verifyMetaSignature(
        req
      )
    ) {

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
 * THREADS WEBHOOK
 * ======================================================
 */

app.get(

  "/threads",

  function (
    req,
    res
  ) {

    const mode =
      req.query[
        "hub.mode"
      ];


    const token =
      req.query[
        "hub.verify_token"
      ];


    const challenge =
      req.query[
        "hub.challenge"
      ];


    if (
      mode ===
        "subscribe" &&

      VERIFY_TOKEN &&

      token ===
        VERIFY_TOKEN &&

      challenge
    ) {

      return res
        .status(200)
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


app.post(

  "/threads",

  function (
    req,
    res
  ) {

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

  function (
    req,
    res
  ) {

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
 * UNHANDLED ERRORS
 * ======================================================
 */

process.on(

  "unhandledRejection",

  function (
    reason
  ) {

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
