import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import Llmstxt from './components/llmstxt.vue'

export default {
  extends : DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'doc-footer-before': () => h(Llmstxt)
    })
  },
}
