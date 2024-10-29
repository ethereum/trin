<script setup>
import { cn } from '@/lib/utils'
import { NumberFieldRoot, useForwardPropsEmits } from 'radix-vue'
import { computed } from 'vue'

const props = defineProps({
  defaultValue: { type: Number, required: false },
  modelValue: { type: Number, required: false },
  min: { type: Number, required: false },
  max: { type: Number, required: false },
  step: { type: Number, required: false },
  formatOptions: { type: null, required: false },
  locale: { type: String, required: false },
  disabled: { type: Boolean, required: false },
  required: { type: Boolean, required: false },
  name: { type: String, required: false },
  id: { type: String, required: false },
  asChild: { type: Boolean, required: false },
  as: { type: null, required: false },
  class: { type: null, required: false }
})
const emits = defineEmits(['update:modelValue'])

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})

const forwarded = useForwardPropsEmits(delegatedProps, emits)
</script>

<template>
  <NumberFieldRoot v-bind="forwarded" :class="cn('grid gap-1.5', props.class)">
    <slot />
  </NumberFieldRoot>
</template>
