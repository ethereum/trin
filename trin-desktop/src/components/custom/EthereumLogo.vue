// components/EthereumLogo.vue
<template>
  <div class="ethereum-logo" :style="containerStyle">
    <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <!-- Lines -->
      <g class="lines-group">
        <path
          v-for="i in 6"
          :key="`line${i}`"
          :id="`line${i}`"
          :d="getLineData(i).d"
          :stroke="currentLineColor"
          stroke-width="1"
        >
          <!-- Position animation -->
          <animate
            :id="`line${i}Anim`"
            attributeName="d"
            :values="getLineAnimationValues(i)"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
          <!-- Color animation -->
          <animate
            :id="`line${i}Color`"
            attributeName="stroke"
            :values="colorValues"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
          <!-- Simple shimmer effect -->
          <animate
            attributeName="stroke-opacity"
            values="1;0.4;0.8;0.3;0.9;0.5;1"
            :dur="`${3 + i * 0.4}s`"
            repeatCount="indefinite"
            begin="0s"
          />
        </path>
      </g>

      <!-- Top Diamond -->
      <g>
        <path id="topDiamond" :d="topDiamondData.d" :fill="diamondFill">
          <animate
            id="topDiamondAnim"
            attributeName="d"
            :values="topDiamondData.values"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
        </path>
        <path :d="topDiamondData.line1" fill="none" :stroke="diamondLines" stroke-width="1">
          <animate
            id="topLine1Anim"
            attributeName="d"
            :values="topDiamondData.line1Values"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
        </path>
        <path :d="topDiamondData.line2" fill="none" :stroke="diamondLines" stroke-width="1">
          <animate
            id="topLine2Anim"
            attributeName="d"
            :values="topDiamondData.line2Values"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
        </path>
      </g>

      <!-- Bottom Diamond -->
      <g>
        <path id="bottomDiamond" :d="bottomDiamondData.d" :fill="diamondFill">
          <animate
            id="bottomDiamondAnim"
            attributeName="d"
            :values="bottomDiamondData.values"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
        </path>
        <path :d="bottomDiamondData.line" fill="none" :stroke="diamondLines" stroke-width="1">
          <animate
            id="bottomLineAnim"
            attributeName="d"
            :values="bottomDiamondData.lineValues"
            dur="0.5s"
            fill="freeze"
            begin="indefinite"
          />
        </path>
      </g>
    </svg>
  </div>
</template>

<script>
import { computed } from 'vue'
import { useTheme } from '@/composables/useTheme'

export default {
  name: 'EthereumLogo',

  props: {
    isOpen: {
      type: Boolean,
      default: false
    },
    size: {
      type: Number,
      default: 400
    }
  },

  setup(props) {
    const { isDark } = useTheme()

    const colorScheme = computed(() => ({
      light: {
        closed: '#FF0000', // Red
        transit: '#FFFF00', // Yellow
        open: '#00FF00', // Green
        diamond: '#000000', // Black
        lines: '#FFFFFF' // White
      },
      dark: {
        closed: '#FF6B6B', // Light red
        transit: '#FFE66D', // Light yellow
        open: '#6BCB77', // Light green
        diamond: '#FFFFFF', // White
        lines: '#000000' // Black
      }
    }))

    const currentScheme = computed(() =>
      isDark.value ? colorScheme.value.dark : colorScheme.value.light
    )

    const currentLineColor = computed(() =>
      props.isOpen ? currentScheme.value.open : currentScheme.value.closed
    )

    const colorValues = computed(() =>
      props.isOpen
        ? `${currentScheme.value.closed};${currentScheme.value.transit};${currentScheme.value.open}`
        : `${currentScheme.value.open};${currentScheme.value.transit};${currentScheme.value.closed}`
    )

    const diamondFill = computed(() => currentScheme.value.diamond)
    const diamondLines = computed(() => currentScheme.value.lines)

    const containerStyle = computed(() => ({
      width: `${props.size}px`,
      height: `${props.size}px`,
      cursor: 'pointer'
    }))

    return {
      currentLineColor,
      colorValues,
      diamondFill,
      diamondLines,
      containerStyle
    }
  },

  data() {
    return {
      lineData: {
        1: {
          d: 'M31,55.1 L31,61',
          opening: 'M31,55.1 L31,61;M31,45.1 L31,71',
          closing: 'M31,45.1 L31,71;M31,55.1 L31,61'
        },
        2: {
          d: 'M41,55 L41,67',
          opening: 'M41,55 L41,67;M41,45 L41,77',
          closing: 'M41,45 L41,77;M41,55 L41,67'
        },
        3: {
          d: 'M51,55 L51,73',
          opening: 'M51,55 L51,73;M51,45 L51,83',
          closing: 'M51,45 L51,83;M51,55 L51,73'
        },
        4: {
          d: 'M59,55 L59,73',
          opening: 'M59,55 L59,73;M59,45 L59,83',
          closing: 'M59,45 L59,83;M59,55 L59,73'
        },
        5: {
          d: 'M69,55 L69,67',
          opening: 'M69,55 L69,67;M69,45 L69,77',
          closing: 'M69,45 L69,77;M69,55 L69,67'
        },
        6: {
          d: 'M79,55.1 L79,61',
          opening: 'M79,55.1 L79,61;M79,45.1 L79,71',
          closing: 'M79,45.1 L79,71;M79,55.1 L79,61'
        }
      }
    }
  },

  computed: {
    topDiamondData() {
      return {
        d: 'M55,15 L80,55 L55,70 L30,55 Z',
        values: this.isOpen
          ? 'M55,15 L80,55 L55,70 L30,55 Z;M55,5 L80,45 L55,60 L30,45 Z'
          : 'M55,5 L80,45 L55,60 L30,45 Z;M55,15 L80,55 L55,70 L30,55 Z',
        line1: 'M55,15 L55,70',
        line1Values: this.isOpen ? 'M55,15 L55,70;M55,5 L55,60' : 'M55,5 L55,60;M55,15 L55,70',
        line2: 'M30,55 L55,44 L80,55',
        line2Values: this.isOpen
          ? 'M30,55 L55,44 L80,55;M30,45 L55,34 L80,45'
          : 'M30,45 L55,34 L80,45;M30,55 L55,44 L80,55'
      }
    },

    bottomDiamondData() {
      return {
        d: 'M55,75 L80,60 L55,90 L30,60 Z',
        values: this.isOpen
          ? 'M55,75 L80,60 L55,90 L30,60 Z;M55,85 L80,70 L55,100 L30,70 Z'
          : 'M55,85 L80,70 L55,100 L30,70 Z;M55,75 L80,60 L55,90 L30,60 Z',
        line: 'M55,73 L55,92',
        lineValues: this.isOpen ? 'M55,73 L55,92;M55,83 L55,102' : 'M55,83 L55,102;M55,73 L55,92'
      }
    }
  },

  methods: {
    getLineData(index) {
      return this.lineData[index]
    },

    getLineAnimationValues(index) {
      return this.isOpen ? this.lineData[index].opening : this.lineData[index].closing
    },

    triggerAnimations() {
      const animations = [
        'topDiamondAnim',
        'bottomDiamondAnim',
        'topLine1Anim',
        'topLine2Anim',
        'bottomLineAnim',
        ...Array.from({ length: 6 }, (_, i) => `line${i + 1}Anim`),
        ...Array.from({ length: 6 }, (_, i) => `line${i + 1}Color`)
      ]

      animations.forEach((id) => {
        const elem = document.getElementById(id)
        if (elem) elem.beginElement()
      })
    }
  },

  watch: {
    isOpen() {
      this.$nextTick(() => {
        this.triggerAnimations()
      })
    }
  }
}
</script>

<style scoped>
.ethereum-logo {
  display: flex;
  align-items: center;
  justify-content: center;
}

svg {
  width: 100%;
  height: 100%;
}
</style>
