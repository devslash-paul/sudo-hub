self.addEventListener('push', event => {
  const value = event.data ? event.data.json() : {title:'Codex approval requested', body:'Open the approval app'};
  event.waitUntil(Promise.all([
    self.registration.showNotification(value.title, {body:value.body, tag:value.tag, data:{url:value.url}}),
    self.registration.navigationPreload ? Promise.resolve() : Promise.resolve()
  ]));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url=event.notification.data?.url || '/';
  event.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(windows => {
    for (const client of windows) { if ('focus' in client) { client.navigate(url); return client.focus(); } }
    return clients.openWindow(url);
  }));
});
