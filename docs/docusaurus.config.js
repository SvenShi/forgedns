import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'OxiDNS',
  tagline: 'A Rust-powered DNS engine inspired by MosDNS, designed for performance and complete configurability.',
  favicon: 'img/logo-light.png',

  scripts: [
    {
      src: '/js/theme-favicon.js',
      defer: true,
    },
  ],

  future: {
    v4: true,
  },

  url: 'https://oxidns.cn',
  baseUrl: '/',

  organizationName: 'SvenShi',
  projectName: 'oxidns',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'zh-Hans',
    locales: ['zh-Hans', 'en'],
    localeConfigs: {
      'zh-Hans': {
        label: '中文',
      },
      en: {
        label: 'English',
      },
    },
  },

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themes: ['@docusaurus/theme-mermaid'],

  plugins: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        docsRouteBasePath: '/',
        indexDocs: true,
        indexBlog: false,
        indexPages: false,
        language: ['zh', 'en'],
        highlightSearchTermsOnTargetPage: true,
        searchBarShortcut: true,
        searchBarShortcutHint: true,
        searchResultLimits: 8,
        explicitSearchResultPath: true,
      },
    ],
  ],

  presets: [
    [
      '@docusaurus/preset-classic',
      ({
        docs: {
          path: './docs',
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/SvenShi/oxidns/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig: ({
      colorMode: {
        defaultMode: 'light',
        disableSwitch: false,
        respectPrefersColorScheme: false,
      },
      navbar: {
        title: 'OxiDNS',
        logo: {
          alt: 'OxiDNS Logo',
          src: 'img/logo-light.png',
          srcDark: 'img/logo-dark.png',
          width: 32,
          height: 32,
        },
        items: [
          {
            type: 'localeDropdown',
            position: 'right',
          },
          {
            href: 'https://github.com/SvenShi/oxidns',
            'aria-label': 'GitHub repository',
            className: 'header-github-link',
            position: 'right',
          },
          {
            type: 'search',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'light',
        links: [
        ],
        copyright: `Copyright © ${new Date().getFullYear()} OxiDNS`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.vsDark,
      },
    }),
};

export default config;
