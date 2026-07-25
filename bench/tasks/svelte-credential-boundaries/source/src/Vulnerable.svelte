<script lang="ts">
  const untrusted = new URLSearchParams(location.search).get("message") ?? "";
  const accessToken = "synthetic-access-token";
  localStorage.setItem("access_token", accessToken);
</script>

<main>
  <a href="https://external.example.test" target="_blank">open external</a>
  {@html untrusted}
</main>
