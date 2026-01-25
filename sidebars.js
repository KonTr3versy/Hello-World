/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    "index",
    {
      type: "category",
      label: "Categories",
      items: [
        "categories/active-directory",
        "categories/cloud",
        "categories/web",
        "categories/red-team",
        "categories/wireless",
        "categories/osint",
      ],
    },
    {
      type: "category",
      label: "Tools",
      items: [
        {
          type: "category",
          label: "Active Directory",
          items: [
            "tools/active-directory/bloodhound",
            "tools/active-directory/ldapdomaindump",
          ],
        },
        {
          type: "category",
          label: "Cloud",
          items: [
            "tools/cloud/prowler",
            "tools/cloud/scout-suite",
          ],
        },
        {
          type: "category",
          label: "Web",
          items: [
            "tools/web/nuclei",
            "tools/web/zap",
          ],
        },
        {
          type: "category",
          label: "Red Team",
          items: [
            "tools/red-team/caldera",
            "tools/red-team/sliver",
          ],
        },
        {
          type: "category",
          label: "Wireless",
          items: [
            "tools/wireless/aircrack-ng",
            "tools/wireless/kismet",
          ],
        },
        {
          type: "category",
          label: "OSINT",
          items: [
            "tools/osint/maltego",
            "tools/osint/theharvester",
          ],
        },
      ],
    },
  ],
};

module.exports = sidebars;
