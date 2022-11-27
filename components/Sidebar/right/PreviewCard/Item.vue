<template>
  <div
    class="p-3 border-b hover:bg-gray-100 cursor-pointer dark:bg-dim-400 dark:hover:bg-dim-300"
    :class="wrapper"
  >
    <slot></slot>
  </div>
</template>

<script setup>

const { defaultTransition, twitterBordeColor } = useTailwindConfig();

const wrapper = computed(()=>`${defaultTransition} ${twitterBordeColor}`)
</script>
