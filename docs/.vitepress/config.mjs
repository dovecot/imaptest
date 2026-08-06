import { defineConfig } from 'vitepress'
import llmstxtPlugin from 'vitepress-plugin-llmstxt'

const base = 'imaptest'
const hostname = `https://dovecot.github.io/${base}/`

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base: `/${base}/`,
  title: "IMAP Server Tester",
  lang: 'en-US',
  description: "Documentation for the IMAP Server Tester",

  vite: {
    plugins: [
      llmstxtPlugin({
        hostname: hostname,
      }),
    ],
  },

  sitemap: {
    hostname: hostname,
  },

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Configuration', link: '/configuration' },
      { text: 'Download', link: '/download' },
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
          { text: 'Download', link: '/download' },
          { text: 'Build', link: '/build' },
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
          { text: 'LLM Resources', link: '/llms' },
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
