const path = require("path");
const axios = require("axios");

const expressModulePath = require.resolve("express");
const originalExpress = require(expressModulePath);

const VK_APP_ID = process.env.VK_APP_ID || "54695788";
const VK_REDIRECT_URI = "https://auth.enzhicrew.ru/vk-auth";

function getProxy() {
  const proxyUrl = process.env.VK_FIXIE_URL;
  if (!proxyUrl) return false;
  const parsed = new URL(proxyUrl);
  return {
    protocol: parsed.protocol.replace(":", ""),
    host: parsed.hostname,
    port: Number(parsed.port || 80),
    auth: {
      username: decodeURIComponent(parsed.username),
      password: decodeURIComponent(parsed.password),
    },
  };
}

function patchedExpress() {
  const app = originalExpress();

  app.use(originalExpress.json());

  app.get("/vk-auth", function (req, res) {
    return res.sendFile(path.join(__dirname, "public", "vk-auth.html"));
  });

  app.post("/vk/token", async function (req, res) {
    const { code, device_id, code_verifier, state } = req.body || {};

    if (!code || !device_id || !code_verifier || !state) {
      return res.status(400).json({
        success: false,
        error: "code, device_id, code_verifier and state are required",
      });
    }

    try {
      const query = new URLSearchParams({
        grant_type: "authorization_code",
        redirect_uri: VK_REDIRECT_URI,
        client_id: String(VK_APP_ID),
        code_verifier: String(code_verifier),
        state: String(state),
        device_id: String(device_id),
      });

      const body = new URLSearchParams({ code: String(code) });

      const response = await axios.post(
        `https://id.vk.ru/oauth2/auth?${query.toString()}`,
        body.toString(),
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          proxy: getProxy(),
          timeout: 30000,
        }
      );

      const data = response.data || {};

      if (data.error) {
        return res.status(400).json({ success: false, vk: data });
      }

      if (data.state && data.state !== state) {
        return res.status(403).json({
          success: false,
          error: "VK OAuth state mismatch",
        });
      }

      return res.json({
        success: true,
        access_token: data.access_token || "",
        refresh_token: data.refresh_token || "",
        user_id: data.user_id || "",
        expires_in: data.expires_in || null,
        scope: data.scope || "",
        device_id: device_id,
      });
    } catch (error) {
      const details = error.response?.data || error.message;
      console.error("VK token exchange error:", details);
      return res.status(500).json({
        success: false,
        error: error.response?.data?.error_description || error.response?.data?.error || error.message,
        details,
      });
    }
  });

  return app;
}

Object.assign(patchedExpress, originalExpress);
Object.setPrototypeOf(patchedExpress, originalExpress);
require.cache[expressModulePath].exports = patchedExpress;
