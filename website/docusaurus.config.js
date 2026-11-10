// Lonca's documentation site, at https://selcukgural.github.io/lonca/.
//
// The pages are the Markdown files in ../docs (the guide, the protocol,
// cryptography, the OWASP review and the release notes), so they read on
// GitHub as they are; this folder holds only the site. Patterned on imece's
// and Kule's sites (website/ in those repositories).
// @ts-check

import fs from 'node:fs';
import path from 'node:path';
import { themes as prismThemes } from 'prism-react-renderer';

const repo = 'https://github.com/selcukgural/lonca';

// The release the site describes: the workspace's version in ../Cargo.toml,
// the one every crate shares, so the site never names an older one. The
// build runs in website/ (docs.yml, npm run build).
function workspaceVersion() {
  const cargo = fs.readFileSync(path.join(process.cwd(), '..', 'Cargo.toml'), 'utf8');
  const block = /^\[workspace\.package\]$([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(cargo);
  const version = block && /^version\s*=\s*"([^"]+)"/m.exec(block[1]);
  if (!version) throw new Error('no [workspace.package] version in ../Cargo.toml');
  return version[1];
}
const version = workspaceVersion();

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Lonca',
  tagline: 'Agent-native, Git-compatible version control',
  favicon: 'img/favicon.svg',
  customFields: { version },

  url: 'https://selcukgural.github.io',
  baseUrl: '/lonca/',
  organizationName: 'selcukgural',
  projectName: 'lonca',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  markdown: {
    // .md pages are CommonMark, not MDX: `<name>` in prose stays text.
    format: 'detect',
    hooks: { onBrokenMarkdownLinks: 'throw' },
  },

  i18n: { defaultLocale: 'en', locales: ['en'] },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../docs',
          // design.md is Turkish and decisions.md is a working record:
          // both are linked on GitHub instead. The checklist is the
          // maintainer's.
          include: [
            'guide/**/*.md',
            'protocol.md',
            'crypto.md',
            'security/threat-model.md',
            'security/owasp.md',
            'release-notes.md',
          ],
          routeBasePath: 'docs',
          sidebarPath: './sidebars.js',
          editUrl: `${repo}/edit/main/website/`,
          showLastUpdateTime: false,
        },
        blog: false,
        theme: { customCss: './src/css/custom.css' },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: { respectPrefersColorScheme: true },
      // Link previews take no SVG: lonca-banner.png is lonca-banner.svg,
      // rendered (rsvg-convert -w 1280).
      image: 'img/lonca-banner.png',
      navbar: {
        title: 'Lonca',
        logo: { alt: 'Lonca', src: 'img/lonca-mark.svg' },
        items: [
          { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
          { to: '/docs/guide/claude-code', label: 'Claude Code', position: 'left' },
          { to: '/docs/guide/install', label: 'Install', position: 'left' },
          { to: '/docs/protocol', label: 'Protocol', position: 'left' },
          { to: '/docs/release-notes', label: 'Release notes', position: 'left' },
          {
            to: '/docs/release-notes',
            label: `v${version}`,
            position: 'right',
            className: 'lonca-navbar-version',
            'aria-label': `Lonca ${version}, release notes`,
          },
          { href: repo, label: 'GitHub', position: 'right' },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Start',
            items: [
              { label: 'Install', to: '/docs/guide/install' },
              { label: 'Quick start', to: '/docs/guide/quick-start' },
              { label: 'Lonca with Claude Code', to: '/docs/guide/claude-code' },
              { label: 'Running agents', to: '/docs/guide/runners' },
            ],
          },
          {
            title: 'Reference',
            items: [
              { label: 'Daemon protocol', to: '/docs/protocol' },
              { label: 'Cryptography', to: '/docs/crypto' },
              { label: 'Decisions', href: `${repo}/blob/main/docs/decisions.md` },
            ],
          },
          {
            title: 'Project',
            items: [
              { label: 'GitHub', href: repo },
              { label: 'Releases', href: `${repo}/releases` },
              { label: 'Report a vulnerability', href: `${repo}/security/policy` },
            ],
          },
        ],
        copyright: 'Lonca is open source under the Apache-2.0 license.',
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'toml', 'json', 'rust', 'diff'],
      },
    }),
};

export default config;
