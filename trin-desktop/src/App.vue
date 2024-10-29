<script setup>
import { ref, onMounted } from 'vue'
import { invoke, Channel } from '@tauri-apps/api/core'
import { Button } from '@/components/ui/button'
import { Toaster } from '@/components/ui/toast'
import { useToast } from '@/components/ui/toast'
import { enable, disable } from '@tauri-apps/plugin-autostart';
import { load } from '@tauri-apps/plugin-store'
import { listen } from '@tauri-apps/api/event'
import { useColorMode } from '@vueuse/core'
import {
  Sheet,
  SheetContent,
  SheetClose,
  SheetFooter,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from '@/components/ui/sheet'
import { Label } from '@/components/ui/label'
import {
  NumberField,
  NumberFieldContent,
  NumberFieldDecrement,
  NumberFieldIncrement,
  NumberFieldInput
} from '@/components/ui/number-field'
import { Card, CardContent, CardTitle, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Network, HardDrive } from 'lucide-vue-next'
import { Play, SquareX, Power, Loader2 } from 'lucide-vue-next'
import { Switch } from '@/components/ui/switch'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from '@/components/ui/dropdown-menu'
import { Icon } from '@iconify/vue'
import { useForm } from 'vee-validate'
import { toFormValidator } from '@vee-validate/zod'
import * as z from 'zod'
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  Form
} from '@/components/ui/form'
import EthereumLogo from '@/components/custom/EthereumLogo.vue'
import { useTheme } from '@/composables/useTheme'
import { Progress } from '@/components/ui/progress'

const trinStats = ref({
  cpu: 0
})
const ethLogo = ref('eth-logo.svg')
const isOpen = ref(false)
const { isDark } = useTheme()
const mode = useColorMode()
const { toast } = useToast()
const name = ref('')
const form = ref(null)
// "running" or "stopped" (improve?)
const trinStatus = ref('stopped')
// this variable is used to control the loading spinner
// while launching / shutting down the trin process
const isLaunching = ref(false)
const config = ref({
  storage: 100,
  httpPort: 8545,
  autostart: true
})

function toggleState() {
  isOpen.value = !isOpen.value
}

async function toggleTrinProcess() {
  if (trinStatus.value === 'running') {
    await shutdownTrin()
  } else {
    await launchTrin()
  }
}

async function launchTrin() {
  isLaunching.value = true
  try {
    await invoke('launch_trin', { trinConfig: config.value })
    trinStatus.value = 'running'
  } catch (e) {
    toast({
      title: 'Failed to launch Trin.',
      description: 'Error: ' + e,
      variant: 'destructive'
    })
  }
  isLaunching.value = false
}

async function shutdownTrin() {
  isLaunching.value = true
  try {
    await invoke('shutdown_trin')
    trinStatus.value = 'stopped'
  } catch (e) {
    toast({
      title: 'Failed to shutdown Trin.',
      description: 'Error: ' + e,
      variant: 'destructive'
    })
  }
  isLaunching.value = false
}

const updateConfig = async (values) => {
  try {
    const store = await load('config.json', { autoSave: true })
    if (typeof values.storage !== 'undefined') {
      config.value.storage = values.storage
      await store.set('storage', config.value.storage)
    }
    if (typeof values.httpPort !== 'undefined') {
      config.value.httpPort = values.httpPort
      await store.set('httpPort', config.value.httpPort)
    }
    if (typeof values.autostart !== 'undefined') {
	  // enable/disable autostart
	  if (values.autostart) {
		await enable();
	  } else {
	    disable();
	  }
      config.value.autostart = values.autostart
      await store.set('autostart', config.value.autostart)
    }
    toast({ title: 'Configuration updated successfully.' })
  } catch (e) {
    toast({
      title: 'Failed to update configuration.',
      description: 'Error: ' + e,
      variant: 'destructive'
    })
  }
}

listen('trin-crashed', (status) => {
  trinStatus.value = 'stopped'
  toast({
    title: 'Trin process has crashed! Restarting your node.',
    variant: 'destructive'
  })
  launchTrin()
})

listen('trin-stats', (stats) => {
  trinStats.value.cpu = stats.payload.cpu
})

const configSchema = z.object({
  storage: z.number().min(100),
  httpPort: z.number().min(0).max(65535),
  autostart: z.boolean()
})

// Initialize form after getting config
const initForm = () => {
  form.value = useForm({
    validationSchema: toFormValidator(configSchema),
    defaultValues: {
      storage: config.value.storage,
      httpPort: config.value.httpPort,
      autostart: config.value.autostart
    }
  })
}

onMounted(async () => {
  const store = await load('config.json', { autoSave: true })
  const httpPort = await store.get('httpPort')

  // Initialize the store with default values
  if (!httpPort) {
    store.set('httpPort', 8545)
    store.set('storage', 100)
    store.set('autostart', true)
    config.value.httpPort = 8545
	// todo: change to 1 gb
    config.value.storage = 100
    config.value.autostart = true
  } else {
    config.value.httpPort = httpPort
    config.value.storage = await store.get('storage')
    config.value.autostart = await store.get('autostart')
    // Launch Trin if autostart is enabled
	// "autostart" currently means that the user wants to launch
	// the Trin process when the app starts and re-launch
	// the app when the system reboots
    if (config.value.autostart) {
      await launchTrin()
    }
  }
  initForm()
})
</script>

<template>
  <main class="min-h-screen w-full bg-background">
    <header
      class="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60"
    >
      <div class="container flex h-14 items-center">
        <slot name="header">
          <h1 class="text-lg font-semibold">Welcome to Trin...</h1>
        </slot>
      </div>
    </header>
    <!-- Main content section -->
    <div class="container py-6" style="margin: 0 auto; width: fit-content">
      <Card>
        <CardHeader>
          <CardTitle class="flex items-center justify-between">
            <span>Process Control</span>
            <Badge :variant="trinStatus === 'running' ? 'success' : 'secondary'">
              {{ trinStatus === 'running' ? 'Running' : 'Stopped' }}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent class="grid gap-4 py-6">
          <EthereumLogo :is-open="trinStatus === 'running'" />
          <!-- Controls -->
          <div class="flex space-x-2">
            <Button
              :variant="trinStatus === 'running' ? 'destructive' : 'default'"
              :disabled="isLaunching"
              @click="toggleTrinProcess"
              class="flex-1"
            >
              <template v-if="!isLaunching">
                <Play v-if="trinStatus !== 'running'" class="mr-2 h-4 w-4" />
                <SquareX v-else class="mr-2 h-4 w-4" />
                {{ trinStatus === 'running' ? 'Shutdown Trin' : 'Launch Trin' }}
              </template>
              <Loader2 v-else class="mr-2 h-4 w-4 animate-spin" />
            </Button>
          </div>
        </CardContent>
      </Card>
      <Card class="p-4" v-if="trinStatus === 'running'">
        <CardHeader class="flex flex-row items-center justify-between pb-2">
          <CardTitle class="text-sm font-medium">CPU Usage</CardTitle>
          <p class="text-sm font-medium text-gray-600">{{ trinStats.cpu.toFixed(2) }}%</p>
        </CardHeader>
        <CardContent>
          <Progress v-model="trinStats.cpu" />
          <p class="py-1 text-xs text-muted-foreground">
            Current CPU being consumed by your Trin node.
          </p>
        </CardContent>
      </Card>
      <Card class="p-4">
        <CardHeader class="flex flex-row items-center justify-between pb-2">
          <CardTitle class="text-sm font-medium">Storage Allocated</CardTitle>
          <HardDrive class="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div class="text-2xl font-bold">{{ config.storage }} MB</div>
          <p class="text-xs text-muted-foreground">
            Total amount of storage that will be consumed by your Trin client.
          </p>
        </CardContent>
      </Card>
      <Card class="p-4">
        <CardHeader class="flex flex-row items-center justify-between pb-2">
          <CardTitle class="text-sm font-medium">HTTP Port</CardTitle>
          <Network class="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div class="text-2xl font-bold">{{ config.httpPort }}</div>
          <p class="text-xs text-muted-foreground">Active HTTP port for JSON-RPC server</p>
        </CardContent>
      </Card>
    </div>
    <DropdownMenu>
      <DropdownMenuTrigger as-child class="absolute z-50">
        <Button variant="outline" id="darkMode">
          <Icon
            icon="radix-icons:moon"
            class="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0"
          />
          <Icon
            icon="radix-icons:sun"
            class="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100"
          />
          <span class="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem @click="mode = 'light'"> Light </DropdownMenuItem>
        <DropdownMenuItem @click="mode = 'dark'"> Dark </DropdownMenuItem>
        <DropdownMenuItem @click="mode = 'auto'"> System </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
    <Sheet>
      <SheetTrigger as-child class="absolute z-50">
        <Button variant="outline" id="configureButton" :disabled="trinStatus === 'running'">
          Configure
        </Button>
      </SheetTrigger>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>Configure Trin</SheetTitle>
          <SheetDescription>
            Update the settings for your Trin node here. Click save when you're done.
          </SheetDescription>
        </SheetHeader>
        <div class="grid gap-4 py-4">
          <div class="grid items-center gap-4">
            <!-- TODO: there's a bit of a bug here, if the form is adjusted but closed instead of submitted, the config values are updated, but it's not saved to disk. so we want to revert the form values back to the original config values -->
            <Form :form="form" @submit="updateConfig">
              <FormField v-slot="{ field }" name="storage" :control="form.control">
                <FormItem>
                  <FormLabel>Storage (MB)</FormLabel>
                  <FormControl>
                    <NumberField
                      class="gap-2"
                      :min="100"
                      v-bind="field"
                      :model-value="config.storage"
                      @update:model-value="
                        (v) => {
                          field.onChange(v)
                          if (v) {
                            config.storage = v
                          } else {
                            config.storage = 100
                          }
                        }
                      "
                    >
                      <NumberFieldContent>
                        <NumberFieldDecrement />
                        <NumberFieldInput />
                        <NumberFieldIncrement />
                      </NumberFieldContent>
                    </NumberField>
                  </FormControl>
                  <FormDescription>
                    Enter the amount of storage you want to allocate to your Trin node.
                  </FormDescription>
                </FormItem>
              </FormField>
              <br />
              <FormField v-slot="{ field }" name="httpPort" :control="form.control">
                <FormItem>
                  <FormLabel>HTTP Port</FormLabel>
                  <FormControl>
                    <NumberField
                      class="gap-2"
                      :min="1024"
                      :max="65535"
                      :format-options="{
                        useGrouping: false
                      }"
                      v-bind="field"
                      :model-value="config.httpPort"
                      @update:model-value="
                        (v) => {
                          field.onChange(v)
                          if (v) {
                            config.httpPort = v
                          } else {
                            config.httpPort = 8545
                          }
                        }
                      "
                    >
                      <NumberFieldContent>
                        <NumberFieldDecrement />
                        <NumberFieldInput />
                        <NumberFieldIncrement />
                      </NumberFieldContent>
                    </NumberField>
                  </FormControl>
                  <FormDescription>
                    Enter the HTTP port for your Trin node (default: 8545).
                  </FormDescription>
                </FormItem>
              </FormField>
              <br />
              <FormField v-slot="{ field }" name="autostart" :control="form.control">
                <FormItem>
                  <div class="flex items-center justify-between">
                    <FormLabel>Autostart</FormLabel>
                    <FormControl>
                      <Switch
                        v-bind="field"
                        :checked="config.autostart"
                        @update:checked="
                          (checked) => {
                            field.onChange(checked)
                            config.autostart = checked
                          }
                        "
                      />
                    </FormControl>
                  </div>
                  <FormDescription>
                    Automatically launch Trin Desktop when system boots.
                  </FormDescription>
                </FormItem>
              </FormField>
              <SheetFooter class="py-6">
                <SheetClose as-child>
                  <Button type="submit"> Submit </Button>
                </SheetClose>
              </SheetFooter>
            </Form>
          </div>
        </div>
      </SheetContent>
    </Sheet>
    <Toaster />
  </main>
</template>

<style scoped>
.logo.vite:hover {
  filter: drop-shadow(0 0 2em #747bff);
}

.logo.vue:hover {
  filter: drop-shadow(0 0 2em #249b73);
}

#darkMode {
  position: fixed;
  top: 0.5rem;
  right: 1rem;
}
#configureButton {
  position: fixed;
  top: 0.5rem;
  right: 5rem;
}
</style>
