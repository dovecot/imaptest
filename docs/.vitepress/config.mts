import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base: '/imaptest/',
  title: "IMAP Server Tester",
  lang: 'en-US',
  description: "Documentation for the IMAP Server Tester",
  srcExclude: [ '/DOCS.md' ],

  sitemap: {
    hostname: 'https://dovecot.github.io/imaptest/',
  },

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Configuration', link: '/configuration' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Features', link: '/features' },
          { text: 'Benchmarking', link: '/benchmarking' },
          { text: 'Compliancy', link: '/compliancy' },
        ]
      },
      {
        text: 'Installation',
        items: [
          { text: 'Installation', link: '/installation' },
        ]
      },
      {
        text: 'Operation',
        items: [
          { text: 'Configuration', link: '/configuration' },
          { text: 'Scripted Testing', link: '/scripted_test' },
          { text: 'States', link: '/states' },
          { text: 'Profile', link: '/profile' },
          { text: 'Examples', link: '/examples' },
        ]
      },
      {
        items: [
          { text: 'Authors', link: '/authors' },
          { text: 'License', link: '/license' },
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/dovecot/imaptest/' }
    ],

    outline: 'deep',
    externalLinkIcon: true,

    search: {
      provider: 'local'
    },
  }
})
