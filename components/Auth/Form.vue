<template>
  <div class="">
    <div class="pt-5 space-y-6">
      <UIInput
        label="Username"
        placeholder="@username"
        v-model="data.username"
      />
      <UIInput
        label="Password"
        placeholder="*********"
        type="password"
        v-model="data.password"
      />
      <div class="">
        <button @click="handleLogin">Submit</button>
      </div>
    </div>
  </div>
</template>

<script setup>
const data = reactive({
  password: "",
  username: "",
});

function handleLogin(){
  alert(JSON.stringify(data))
}
</script>
