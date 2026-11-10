// The order of the docs. Every page the site takes from ../docs is listed
// here by its id (its path without .md); check.sh fails the build when a
// page in docs/guide is missing.
// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    { type: 'doc', id: 'guide/index', label: 'What Lonca is' },
    {
      type: 'category',
      label: 'Getting started',
      collapsed: false,
      items: [
        { type: 'doc', id: 'guide/install', label: 'Install' },
        { type: 'doc', id: 'guide/quick-start', label: 'Quick start' },
        { type: 'doc', id: 'guide/concepts', label: 'Concepts' },
        { type: 'doc', id: 'guide/claude-code', label: 'Lonca with Claude Code' },
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        { type: 'doc', id: 'guide/humans', label: 'Working as a human' },
        { type: 'doc', id: 'guide/reviewing', label: "Reviewing agents' work" },
        { type: 'doc', id: 'guide/profiles', label: 'Profiles' },
        { type: 'doc', id: 'guide/policies', label: 'Writing policies' },
        { type: 'doc', id: 'guide/runners', label: 'Running agents' },
        { type: 'doc', id: 'guide/verification', label: 'Verification' },
        { type: 'doc', id: 'guide/recovery', label: 'Recovery' },
        { type: 'doc', id: 'guide/troubleshooting', label: 'Troubleshooting' },
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        { type: 'doc', id: 'protocol', label: 'Daemon protocol' },
        { type: 'doc', id: 'security/threat-model', label: 'Threat model' },
        { type: 'doc', id: 'crypto', label: 'Cryptography' },
        { type: 'doc', id: 'security/owasp', label: 'OWASP review' },
      ],
    },
    { type: 'doc', id: 'release-notes', label: 'Release notes' },
  ],
};

export default sidebars;
