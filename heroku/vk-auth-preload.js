const path = require("path");

/**
 * Preload route for the legacy VK ID authorization page.
 *
 * This keeps the current large heroku/index.js untouched while restoring
 * https://auth.enzhicrew.ru/vk-auth exactly as a standalone page.
 */

const expressModulePath = require.resolve("express");
const originalExpress = require(expressModulePath);

function patchedExpress() {
  const app = originalExpress();

  app.get("/vk-auth", function (req, res) {
    return res.sendFile(
      path.join(__dirname, "public", "vk-auth.html")
    );
  });

  return app;
}

Object.assign(patchedExpress, originalExpress);
Object.setPrototypeOf(patchedExpress, originalExpress);

require.cache[expressModulePath].exports = patchedExpress;
