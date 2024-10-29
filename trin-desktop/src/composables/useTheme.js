// composables/useTheme.js
import { ref, onUnmounted } from 'vue'

export function useTheme() {
  const isDark = ref(document.documentElement.classList.contains('dark'))

  // Watch for theme changes
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.attributeName === 'class') {
        isDark.value = document.documentElement.classList.contains('dark')
      }
    })
  })

  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class']
  })

  // Clean up
  onUnmounted(() => {
    observer.disconnect()
  })

  return {
    isDark
  }
}
