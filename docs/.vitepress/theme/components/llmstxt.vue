<script setup>
import { useRoute, useData } from 'vitepress'
import { computed } from 'vue'

const data = useData()
const route = useRoute()

// Computes the clean, relative LLM Markdown path for the active route.
const llmsPath = computed(() => {
  const pageData = data.site.value.themeConfig?.llmstxt?.pageData
  if (!pageData) return null

  const targetPath = route.data?.filePath
  const item = pageData.find(p => p.path === targetPath || p.url.endsWith(route.path))
  if (!item) return null

  const rawUrl = item.llmUrl || item.path
  return rawUrl.replace(/^https?:\/\/[^\/]+/, '')
})
</script>

<template>
  <div v-if="llmsPath" class="llmstxt-footer-info">
    <a :href="llmsPath" target="_blank" class="link">
      LLM Markdown
    </a>
  </div>
</template>

<style scoped>
.llmstxt-footer-info {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 16px;
  font-size: 14px;
  line-height: 24px;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.llmstxt-footer-info .label {
  color: var(--vp-c-text-2);
}

.llmstxt-footer-info .link {
  color: var(--vp-c-brand-1);
  text-decoration: underline;
  text-underline-offset: 2px;
  transition: color 0.25s;
}

.llmstxt-footer-info .link:hover {
  color: var(--vp-c-brand-2);
}
</style>
