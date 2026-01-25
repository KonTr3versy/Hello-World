// @ts-check

const config = {
  title: "Offensive Security Cheatsheets",
  tagline: "High-signal, authorized-use reference for red team tooling",
  url: "https://example.com",
  baseUrl: "/",
  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",
  favicon: "img/favicon.ico",
  organizationName: "example",
  projectName: "offsec-cheatsheet",
  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */ ({
        docs: {
          sidebarPath: require.resolve("./sidebars.js"),
          routeBasePath: "/",
        },
        blog: false,
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
      }),
    ],
  ],
  themeConfig: /** @type {import('@docusaurus/preset-classic').ThemeConfig} */ ({
    navbar: {
      title: "OffSec Cheatsheets",
      items: [
        {
          type: "doc",
          docId: "index",
          position: "left",
          label: "Home",
        },
        {
          type: "doc",
          docId: "categories/active-directory",
          position: "left",
          label: "Categories",
        },
      ],
    },
    footer: {
      style: "light",
      links: [
        {
          title: "Categories",
          items: [
            { label: "Active Directory", to: "/categories/active-directory" },
            { label: "Cloud", to: "/categories/cloud" },
            { label: "Web", to: "/categories/web" },
            { label: "Red Team", to: "/categories/red-team" },
            { label: "Wireless", to: "/categories/wireless" },
            { label: "OSINT", to: "/categories/osint" },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} OffSec Cheatsheets`,
    },
  }),
};

module.exports = config;
