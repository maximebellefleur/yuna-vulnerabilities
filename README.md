# Yuna Plugin Vulnerabilities

A lightweight WordPress plugin that checks installed plugins and themes for known vulnerabilities and surfaces results inside wp-admin.

## Download URL (accessible from `main` branch)

Use this WordPress-installable ZIP URL from the `main` branch:

**https://github.com/yunadesign/yuna-vulnerabilities/archive/refs/heads/main.zip**

## Version

Current plugin version: **1.2.1**.

## Install in WordPress

1. In WordPress admin, go to **Plugins → Add New Plugin → Upload Plugin**.
2. Upload the ZIP from the download URL above.
3. Click **Install Now**, then **Activate Plugin**.

## Yuna Helper compatibility checklist

- Main plugin file includes required WordPress headers: `Plugin Name`, `Version`, `Update URI`.
- `Update URI` is set to `https://github.com/yunadesign/yuna-vulnerabilities`.
- Version in plugin header is updated to `1.2.1`.
- Repository should create a matching release tag (`v1.2.1`) for production release tracking.

Reference doc: `PLUGIN_ONBOARDING_AI.md`.

## What it does

- Adds a **Vulnerability Check** column in the Plugins table.
- Shows a theme vulnerability table on the Plugins admin page.
- Adds a dashboard widget with vulnerable items and reference links.
- Supports marking items as manually patched.
