// Lives in its own file (not inline in the page) so the Content-Security-Policy
// can block all inline scripts.
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

function postJson(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
    body: JSON.stringify(body || {}),
  });
}

document.getElementById("connect-bank").addEventListener("click", async () => {
  const res = await postJson("/plaid/link_token");
  const data = await res.json();
  if (!res.ok) { alert(data.error); return; }

  Plaid.create({
    token: data.link_token,
    onSuccess: async (public_token) => {
      const exchange = await postJson("/plaid/exchange", { public_token });
      if (!exchange.ok) { alert((await exchange.json()).error); return; }
      window.location.reload();
    },
  }).open();
});
