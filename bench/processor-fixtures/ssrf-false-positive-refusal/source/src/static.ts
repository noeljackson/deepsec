export async function healthcheck() {
  return fetch("https://status.example.com/health");
}
