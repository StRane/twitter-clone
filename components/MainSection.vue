<template>
  <div class="border-x" :class="TwitterBorderColor">
    <div
      class="sticky top-0 px-4 bg-white/80 backdrop-blur-md dark:bg-dim-900/80"
    >
      <h2 class="text-xl font-bold text-gray-800 dark:text-gray-100 py-3">
        {{ props.title }}
      </h2>
    </div>

    <div class="flex items-center justify-center p-4 border-b" v-if="loading" :class="TwitterBorderColor">
      <UISpinner />
    </div>
    <div class="" v-else><slot></slot></div>
  </div>
</template>

<script setup>
const props = defineProps({
  title: {
    type: String,
    required: true,
  },
  loading: {
    type: Boolean,
    required: true,
  },
});

const {TwitterBorderColor}= useTailwindConfig();
</script>
