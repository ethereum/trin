<script setup>
import { cn } from '@/lib/utils'
import { ProgressIndicator, ProgressRoot } from 'radix-vue'
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: [Number, null], required: false, default: 0 },
  max: { type: Number, required: false },
  getValueLabel: { type: Function, required: false },
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
  <ProgressRoot
    v-bind="delegatedProps"
    :class="cn('relative h-2 w-full overflow-hidden rounded-full bg-primary/20', props.class)"
  >
    <ProgressIndicator
      class="h-full w-full flex-1 bg-primary transition-all"
      :style="`transform: translateX(-${100 - (props.modelValue ?? 0)}%);`"
    />
  </ProgressRoot>
</template>
