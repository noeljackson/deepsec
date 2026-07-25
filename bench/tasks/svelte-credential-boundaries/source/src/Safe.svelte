<script lang="ts">
  const untrusted = new URLSearchParams(location.search).get("message") ?? "";
  let accessToken = "";
  accessToken = "returned-at-login";
</script>

<main>
  <a href="https://external.example.test" target="_blank" rel="noopener noreferrer">open external</a>
  <p>{untrusted}</p>
  <p>Escaped Svelte interpolation remains text.</p>
  <p>Tokens stay in memory for the active browser session.</p>
  <p>External navigation cannot retain an opener handle.</p>
  <p>Static fixture padding keeps candidate-density checks meaningful.</p>
  <p>Only the explicitly labelled unsafe shapes are security findings.</p>
  <p>Safe twins should produce no candidates for their paired matcher.</p>
  <p>There is no raw HTML sink in this component.</p>
  <p>There is no browser credential persistence in this component.</p>
  <p>There is no unprotected blank-target link in this component.</p>
</main>
