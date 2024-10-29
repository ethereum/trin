<script setup>
import { cn } from '@/lib/utils'
import { ToastTitle } from 'radix-vue'
import { computed } from 'vue'

const props = defineProps({
  asChild: { type: Boolean, required: false },
  as: { type: null, required: false },
  class: { type: null, required: false }
})

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})
</script>

<template>
  <ToastTitle
    v-bind="delegatedProps"
    :class="cn('text-sm font-semibold [&+div]:text-xs', props.class)"
  >
    <slot />
  </ToastTitle>
</template>
