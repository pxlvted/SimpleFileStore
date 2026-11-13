const state = {
  username: '',
  csrf: '',
  mode: 'folder',
  folderId: null,
  folders: [],
  files: [],
  view: 'list',
  sort: 'name',
  sortDirection: 1,
  authMode: 'login',
  authChallenge: null,
  searchTimer: null,
  refreshTimer: null,
  editing: null,
  originalContent: '',
  selectedIds: new Set(),
  currentUploadRequest: null,
  currentPermissions: null,
  currentFolderName: null,
  sharedNavigationRoot: null,
  sharing: null,
  shareSearchTimer: null
};

const $ = (selector) => document.querySelector(selector);
const authPage = $('#auth');
const application = $('#application');
const svgNamespace = 'http://www.w3.org/2000/svg';

function createIcon(name, className = 'icon') {
  const icon = document.createElementNS(svgNamespace, 'svg');
  icon.classList.add(...className.split(' '));
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('width', '18');
  icon.setAttribute('height', '18');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('focusable', 'false');
  const use = document.createElementNS(svgNamespace, 'use');
  use.setAttribute('href', `#icon-${name}`);
  icon.append(use);
  return icon;
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase()) && state.csrf) {
    headers.set('X-CSRF-Token', state.csrf);
  }
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
  if (!response.ok) {
    const invalidDeletionPassword = url === '/api/auth/delete' && payload?.error === 'Invalid password';
    if (response.status === 401 && !url.includes('/auth/login') && !invalidDeletionPassword) showAuth();
    throw new Error(payload?.error || `Request failed (${response.status})`);
  }
  return payload;
}

function toast(message, isError = false) {
  const node = document.createElement('div');
  node.className = `toast${isError ? ' error' : ''}`;
  node.textContent = message;
  $('#toast-region').append(node);
  setTimeout(() => node.remove(), 4200);
}

function showAuth() {
  clearInterval(state.refreshTimer);
  application.classList.add('hidden');
  authPage.classList.remove('hidden');
  state.csrf = '';
  state.username = '';
  resetAuthChallenge();
}

function showApplication(username, csrfToken) {
  state.username = username;
  state.csrf = csrfToken;
  state.authChallenge = null;
  $('#password').value = '';
  $('#auth-otp-code').value = '';
  $('#profile-name').textContent = username;
  $('#avatar').textContent = username.slice(0, 1).toUpperCase();
  authPage.classList.add('hidden');
  application.classList.remove('hidden');
  state.mode = 'folder';
  state.folderId = null;
  state.sharedNavigationRoot = null;
  loadCurrent();
  loadStorage();
  clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => {
    if (state.files.some((file) => ['PENDING_SCAN', 'SCANNING'].includes(file.status))) loadCurrent();
  }, 3000);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = -1;
  do { value /= 1024; unit += 1; } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

function formatDate(timestamp) {
  if (!timestamp) return '—';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(timestamp);
}

async function loadStorage() {
  try {
    const storage = await api('/api/storage');
    const unlimited = storage.limit === null;
    const percent = unlimited ? 0 : Math.min(100, storage.used / storage.limit * 100);
    const level = Math.round(percent / 5);
    $('#storage-percent').textContent = `${Math.round(percent)}%`;
    $('#storage-bar').className = `fill-level-${level}`;
    $('#storage-text').textContent = unlimited
      ? `${formatBytes(storage.used)} used · unlimited storage`
      : `${formatBytes(storage.used)} of ${formatBytes(storage.limit)} used`;
  } catch (error) { toast(error.message, true); }
}

async function loadCurrent() {
  const title = state.mode === 'folder' ? (state.folderId ? state.currentFolderName || 'Folder' : 'My files') : ({
    recent: 'Recent files', starred: 'Starred', shared: 'Shared with me',
    trash: 'Trash', search: 'Search results', storage: 'Storage'
  }[state.mode] || 'My files');
  $('#page-title').textContent = title;
  $('#section-eyebrow').textContent = state.mode === 'trash' ? 'Trash' : '';
  if (state.mode !== 'storage') $('#storage-page-card')?.classList.add('hidden');
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle(
    'active', item.dataset.mode === state.mode && (state.mode !== 'folder' || (item.dataset.folder || '') === (state.folderId || ''))
  ));
  if (state.mode === 'storage') {
    $('#bulk-actions').classList.add('hidden');
    $('#select-all').disabled = true;
    $('#upload-button').disabled = false;
    $('#empty-upload').disabled = false;
    return renderStoragePage();
  }
  $('#loading').classList.remove('hidden');
  $('#empty-state').classList.add('hidden');
  $('#table-wrap').classList.add('hidden');
  $('#grid-list').classList.add('hidden');
  try {
    const query = $('#search').value.trim();
    const params = new URLSearchParams();
    if (state.mode === 'search' && query) params.set('q', query);
    else if (['recent', 'starred', 'shared', 'trash'].includes(state.mode)) params.set('mode', state.mode);
    else if (state.mode === 'folder' && state.folderId) params.set('folderId', state.folderId);
    const result = await api(`/api/files${params.size ? `?${params}` : ''}`);
    state.files = result.files;
    state.folders = result.folders;
    state.currentPermissions = state.mode === 'folder' ? result.currentPermissions : null;
    state.currentFolderName = state.mode === 'folder' ? result.currentFolder?.name || null : null;
    if (state.mode === 'folder') $('#page-title').textContent = state.folderId ? state.currentFolderName || 'Folder' : 'My files';
    const visibleIds = new Set(state.files.filter((file) => file.permissions?.canRemove).map((file) => file.id));
    state.selectedIds = new Set([...state.selectedIds].filter((fileId) => visibleIds.has(fileId)));
    $('#loading').classList.add('hidden');
    renderBreadcrumbs();
    renderFiles();
    if (state.files.some((file) => ['PENDING_SCAN', 'SCANNING'].includes(file.status))) {
      $('#section-eyebrow').textContent = 'Files are being scanned';
    }
  } catch (error) {
    $('#loading').classList.add('hidden');
    toast(error.message, true);
  }
}

async function renderBreadcrumbs() {
  const container = $('#breadcrumbs');
  container.replaceChildren();
  if (state.mode !== 'folder') return;
  const home = document.createElement('button');
  home.textContent = state.sharedNavigationRoot ? 'Shared with me' : 'My files';
  home.onclick = () => {
    if (state.sharedNavigationRoot) {
      state.mode = 'shared';
      state.folderId = null;
      state.sharedNavigationRoot = null;
    } else state.folderId = null;
    loadCurrent();
  };
  container.append(home);
  if (!state.folderId) return;
  try {
    const path = await api(`/api/folders/${encodeURIComponent(state.folderId)}/path`);
    path.folders.forEach((folder, index) => {
      const separator = document.createElement('span');
      separator.append(createIcon('chevron', 'icon breadcrumb-chevron'));
      container.append(separator);
      const crumb = document.createElement('button');
      crumb.textContent = folder.name;
      crumb.onclick = () => {
        state.folderId = folder.id;
        if (index === path.folders.length - 1) loadCurrent();
        else openFolder(folder.id);
      };
      container.append(crumb);
    });
  } catch (error) { toast(error.message, true); }
}

async function openFolder(folderId, isSharedRoot = false) {
  state.selectedIds.clear();
  if (isSharedRoot) state.sharedNavigationRoot = folderId;
  state.mode = 'folder';
  state.folderId = folderId;
  $('#search').value = '';
  $('#clear-search').classList.add('hidden');
  await loadCurrent();
}

function makeStatus(file) {
  const badge = document.createElement('span');
  const labels = {
    PENDING_SCAN: 'Waiting to scan', SCANNING: 'Scanning',
    SCAN_PASSED: 'No threats detected', SUSPICIOUS: 'Suspicious',
    INFECTED: 'Infected', SCAN_FAILED: 'Scan failed',
    UNSCANNABLE: 'Could not inspect', QUARANTINED: 'Quarantined'
  };
  const good = file.status === 'SCAN_PASSED';
  const blocked = ['SUSPICIOUS', 'INFECTED', 'SCAN_FAILED', 'UNSCANNABLE', 'QUARANTINED'].includes(file.status);
  badge.className = `badge${good ? ' passed' : blocked ? ' blocked' : ''}`;
  badge.textContent = labels[file.status] || file.status;
  badge.title = file.detection || (good
    ? 'No threats detected by the built-in scanner. This is not a guarantee of safety.'
    : '');
  return badge;
}

function iconFor(fileName, folder = false) {
  if (folder) return 'folder';
  const extension = fileName.split('.').pop().toLowerCase();
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'].includes(extension)) return 'image';
  if (['mp4', 'mov', 'mkv', 'webm', 'avi'].includes(extension)) return 'video';
  if (['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac'].includes(extension)) return 'audio';
  if (['zip', 'gz', '7z', 'rar', 'tar'].includes(extension)) return 'archive';
  if (['js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx', 'html', 'css', 'json', 'xml', 'yaml', 'yml', 'py', 'c', 'cpp', 'h', 'java', 'sh'].includes(extension)) return 'code';
  return 'document';
}

function actionButton(iconName, action, id, title) {
  const button = document.createElement('button');
  button.type = 'button';
  button.title = title;
  button.setAttribute('aria-label', title);
  button.dataset.action = action;
  button.dataset.id = id;
  button.append(createIcon(iconName));
  if (action === 'star' && title === 'Unstar file') button.classList.add('is-starred');
  return button;
}

function fileNameCell(name, folder, itemId, status, detection) {
  const wrapper = document.createElement('div');
  wrapper.className = 'file-name';
  const icon = document.createElement('span');
  const iconName = iconFor(name, folder);
  icon.className = `file-icon${folder ? ' folder' : ''} file-icon-${iconName}`;
  icon.append(createIcon(iconName));
  const info = document.createElement('div');
  const title = document.createElement(folder ? 'button' : 'span');
  title.className = 'file-title';
  title.textContent = name;
  if (folder) {
    title.type = 'button';
    title.classList.add('folder-title-button');
    title.dataset.action = 'open-folder';
    title.dataset.id = itemId;
    if (!folder.isOwner) {
      const owner = document.createElement('div');
      owner.className = 'file-subtitle';
      owner.textContent = `Shared by ${folder.ownerUsername || 'another user'}`;
      info.append(owner);
    }
  } else {
    const item = state.files.find((file) => file.id === itemId);
    if (item?.ownerUsername && !item.isOwner) {
      const owner = document.createElement('div');
      owner.className = 'file-subtitle';
      owner.textContent = `Shared by ${item.ownerUsername}`;
      info.append(owner);
    }
  }
  info.append(title);
  if (!folder && status !== 'SCAN_PASSED') {
    const subtitle = document.createElement('div');
    subtitle.className = 'file-subtitle';
    subtitle.textContent = ['PENDING_SCAN', 'SCANNING'].includes(status)
      ? 'Unavailable until the scan completes'
      : `Unavailable: ${detection || status}`;
    info.append(subtitle);
  }
  wrapper.append(icon, info);
  return wrapper;
}

function actionsForFolder(folder) {
  const actions = document.createElement('div');
  actions.className = 'row-actions';
  if (folder.isOwner) {
    actions.append(actionButton('move', 'move-folder', folder.id, 'Move folder'));
    actions.append(actionButton('edit', 'rename-folder', folder.id, 'Rename folder'));
    actions.append(actionButton('trash', 'delete-folder', folder.id, 'Move folder to Trash'));
    actions.append(actionButton('share', 'share-folder', folder.id, 'Share folder'));
  }
  return actions;
}

function actionsForFile(file) {
  const actions = document.createElement('div');
  actions.className = 'row-actions';
  if (state.mode === 'trash') {
    if (file.status === 'SCAN_PASSED' || ['PENDING_SCAN', 'SCANNING'].includes(file.status)) {
      actions.append(actionButton('restore', 'restore', file.id, 'Restore file'));
    }
    actions.append(actionButton('close', 'purge', file.id, 'Permanently delete'));
    return actions;
  }
  if (file.status === 'SCAN_PASSED' && file.deletedAt === null) {
    if (file.isOwner) actions.append(actionButton('star', 'star', file.id, file.starred ? 'Unstar file' : 'Star file'));
    if (file.permissions?.canRemove) actions.append(actionButton('move', 'move-file', file.id, 'Move file'));
    actions.append(actionButton('download', 'download', file.id, 'Download file'));
    if (file.permissions?.canEdit && ['txt', 'md', 'json', 'html', 'css', 'js', 'xml', 'csv', 'yaml', 'yml', 'log'].includes(file.name.split('.').pop().toLowerCase())) {
      actions.append(actionButton('edit', 'edit', file.id, 'Edit text file'));
    }
    if (file.permissions?.canRemove) actions.append(actionButton('trash', 'trash', file.id, 'Move to Trash'));
  } else if (file.status !== 'QUARANTINED' && file.permissions?.canRemove) {
    actions.append(actionButton('trash', 'trash', file.id, 'Move to Trash'));
  }
  if (file.isOwner && state.mode !== 'trash') {
    actions.append(actionButton('share', 'share-file', file.id, 'Share file'));
  }
  return actions;
}

function renderFiles() {
  const folders = [...state.folders];
  const files = [...state.files];
  const combined = [
    ...folders.map((folder) => ({ ...folder, kind: 'folder', nameSort: folder.name })),
    ...files.map((file) => ({ ...file, kind: 'file', nameSort: file.name }))
  ];
  combined.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1;
    let order = 0;
    if (state.sort === 'size') order = (a.size || 0) - (b.size || 0);
    else if (state.sort === 'modified_at') order = (a.modifiedAt || 0) - (b.modifiedAt || 0);
    else order = a.nameSort.localeCompare(b.nameSort, undefined, { sensitivity: 'base' });
    return order * state.sortDirection;
  });
  const tbody = $('#file-list');
  const grid = $('#grid-list');
  tbody.replaceChildren();
  grid.replaceChildren();
  for (const item of combined) {
    const isFolder = item.kind === 'folder';
    const tr = document.createElement('tr');
    const selectionCell = document.createElement('td');
    if (!isFolder && state.mode !== 'trash' && item.permissions?.canRemove) {
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'select-file';
      checkbox.setAttribute('aria-label', `Select ${item.name}`);
      checkbox.checked = state.selectedIds.has(item.id);
      checkbox.dataset.id = item.id;
      selectionCell.append(checkbox);
    }
    const nameCell = document.createElement('td');
    nameCell.append(fileNameCell(item.name, isFolder, item.id, item.status, item.detection));
    const sizeCell = document.createElement('td');
    sizeCell.textContent = isFolder ? '—' : formatBytes(item.size);
    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(isFolder ? item.createdAt : item.modifiedAt);
    const statusCell = document.createElement('td');
    if (isFolder) statusCell.textContent = 'Folder';
    else if (state.mode === 'trash') statusCell.textContent = 'In Trash';
    else statusCell.append(makeStatus(item));
    const actionCell = document.createElement('td');
    actionCell.append(isFolder ? actionsForFolder(item) : actionsForFile(item));
    tr.append(selectionCell, nameCell, sizeCell, dateCell, statusCell, actionCell);
    tbody.append(tr);

    const card = document.createElement('article');
    card.className = 'grid-card';
    if (isFolder) card.dataset.action = 'open-folder';
    card.dataset.id = item.id;
    if (!isFolder && state.mode !== 'trash' && item.permissions?.canRemove) {
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'select-file grid-select';
      checkbox.setAttribute('aria-label', `Select ${item.name}`);
      checkbox.checked = state.selectedIds.has(item.id);
      checkbox.dataset.id = item.id;
      card.append(checkbox);
    }
    card.append(fileNameCell(item.name, isFolder, item.id, item.status, item.detection));
    if (!isFolder) card.append(makeStatus(item));
    card.append(isFolder ? actionsForFolder(item) : actionsForFile(item));
    grid.append(card);
  }
  const empty = combined.length === 0;
  $('#empty-state').classList.toggle('hidden', !empty);
  $('#table-wrap').classList.toggle('hidden', empty || state.view !== 'list');
  grid.classList.toggle('hidden', empty || state.view !== 'grid');
  $('#new-folder').classList.toggle('hidden', state.mode !== 'folder');
  $('#new-folder').disabled = Boolean(state.folderId && !state.currentPermissions?.canAdd);
  const canUpload = state.mode !== 'shared'
    && !(state.mode === 'folder' && state.folderId && !state.currentPermissions?.canAdd);
  $('#upload-button').disabled = !canUpload;
  $('#empty-upload').disabled = !canUpload;
  const selectableFiles = state.files.filter((file) => file.permissions?.canRemove);
  const canSelect = state.mode !== 'trash' && state.mode !== 'storage' && selectableFiles.length > 0;
  $('#bulk-actions').classList.toggle('hidden', !canSelect || state.selectedIds.size === 0);
  $('#selection-count').textContent = `${state.selectedIds.size} selected`;
  $('#select-all').checked = selectableFiles.length > 0 && selectableFiles.every((file) => state.selectedIds.has(file.id));
  $('#select-all').disabled = !canSelect;
  if (state.mode === 'trash') {
    let emptyButton = $('#empty-trash');
    if (!emptyButton) {
      emptyButton = document.createElement('button');
      emptyButton.id = 'empty-trash';
      emptyButton.className = 'button secondary';
      emptyButton.textContent = 'Empty trash';
      $('.heading-actions').prepend(emptyButton);
    }
    emptyButton.classList.remove('hidden');
  } else {
    $('#empty-trash')?.classList.add('hidden');
  }
}

async function renderStoragePage() {
  let usage;
  try { usage = await api('/api/storage'); }
  catch (error) {
    $('#loading').classList.add('hidden');
    toast(error.message, true);
    return;
  }
  $('#breadcrumbs').replaceChildren();
  $('#loading').classList.add('hidden');
  $('#empty-state').classList.add('hidden');
  $('#table-wrap').classList.add('hidden');
  $('#grid-list').classList.add('hidden');
  let card = $('#storage-page-card');
  if (!card) {
    card = document.createElement('section');
    card.id = 'storage-page-card';
    card.className = 'storage-card';
    $('#file-area').append(card);
  }
  const unlimited = usage.limit === null;
  const percent = unlimited ? 0 : Math.min(100, usage.used / usage.limit * 100);
  const level = Math.round(percent / 5);
  const storageLimit = unlimited ? 'unlimited' : formatBytes(usage.limit);
  const remaining = unlimited ? 'unlimited' : formatBytes(usage.remaining);
  card.innerHTML = `<p class="eyebrow">Storage</p><strong>${formatBytes(usage.used)}</strong><p class="muted">of ${storageLimit} used · ${remaining} available</p><div class="storage-track"><span class="fill-level-${level}"></span></div><p class="muted">Items in Trash still count toward your storage.</p>`;
}

function setAuthMode(mode) {
  state.authMode = mode;
  const registering = mode === 'register';
  $('#auth-title').textContent = registering ? 'Create your account' : 'Welcome back';
  $('#auth-description').textContent = registering ? 'Register using a username approved by the owner.' : 'Sign in to your private file space.';
  $('#auth-submit').textContent = registering ? 'Create account' : 'Sign in';
  $('#password').autocomplete = registering ? 'new-password' : 'current-password';
  $('#auth-switch-label').textContent = registering ? 'Already registered?' : 'New here?';
  $('#auth-switch').textContent = registering ? 'Sign in' : 'Create an account';
}

function resetAuthChallenge() {
  state.authChallenge = null;
  $('#auth-credentials').classList.remove('hidden');
  $('#username').disabled = false;
  $('#username').required = true;
  $('#password').disabled = false;
  $('#password').required = true;
  $('#auth-otp').classList.add('hidden');
  $('#auth-otp-code').required = false;
  $('#auth-otp-code').value = '';
  $('#auth-submit').textContent = state.authMode === 'register' ? 'Create account' : 'Sign in';
}

$('#auth-switch').addEventListener('click', () => {
  resetAuthChallenge();
  setAuthMode(state.authMode === 'login' ? 'register' : 'login');
});
$('#auth-otp-back').addEventListener('click', resetAuthChallenge);
$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#auth-submit');
  button.disabled = true;
  try {
    if (state.authChallenge) {
      const result = await api('/api/auth/login/otp', {
        method: 'POST',
        body: JSON.stringify({ challengeToken: state.authChallenge, code: $('#auth-otp-code').value })
      });
      showApplication(result.username, result.csrfToken);
      return;
    }
    const data = Object.fromEntries(new FormData(event.currentTarget).entries());
    const result = await api(`/api/auth/${state.authMode}`, { method: 'POST', body: JSON.stringify(data) });
    if (state.authMode === 'register') {
      toast('Account created. You can now sign in.');
      setAuthMode('login');
      $('#password').value = '';
      return;
    }
    if (result.requiresOtp) {
      state.authChallenge = result.challengeToken;
      $('#auth-credentials').classList.add('hidden');
      $('#username').disabled = true;
      $('#username').required = false;
      $('#password').disabled = true;
      $('#password').required = false;
      $('#auth-otp').classList.remove('hidden');
      $('#auth-otp-code').required = true;
      $('#auth-submit').textContent = 'Verify code';
      $('#auth-otp-code').focus();
      return;
    }
    showApplication(result.username, result.csrfToken);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});

async function trySession() {
  try {
    const session = await api('/api/auth/me');
    showApplication(session.username, session.csrfToken);
  } catch { showAuth(); }
}

document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => {
  state.selectedIds.clear();
  state.mode = button.dataset.mode;
  state.folderId = null;
  state.sharedNavigationRoot = null;
  $('#search').value = '';
  $('#clear-search').classList.add('hidden');
  loadCurrent();
}));

document.querySelector('.brand').addEventListener('click', (event) => {
  event.preventDefault();
  state.selectedIds.clear();
  state.selectedIds.clear();
  state.mode = 'folder';
  state.folderId = null;
  loadCurrent();
});

$('#search').addEventListener('input', () => {
  const query = $('#search').value.trim();
  $('#clear-search').classList.toggle('hidden', !query);
  clearTimeout(state.searchTimer);
  state.searchTimer = setTimeout(() => {
    if (query) {
      state.selectedIds.clear();
      state.sharedNavigationRoot = null;
      state.selectedIds.clear();
      state.mode = 'search';
      state.folderId = null;
    } else if (state.mode === 'search') state.mode = 'folder';
    loadCurrent();
  }, 220);
});
$('#clear-search').addEventListener('click', () => { $('#search').value = ''; $('#search').dispatchEvent(new Event('input')); });

function showUploadChoice() {
  $('#upload-choice').classList.remove('hidden');
}

function hideUploadChoice() {
  $('#upload-choice').classList.add('hidden');
}

$('#upload-button').addEventListener('click', showUploadChoice);
$('#empty-upload').addEventListener('click', showUploadChoice);
$('#choose-files').addEventListener('click', () => {
  hideUploadChoice();
  $('#file-picker').click();
});
$('#choose-folder').addEventListener('click', () => {
  hideUploadChoice();
  $('#folder-picker').click();
});
$('#upload-choice-cancel').addEventListener('click', hideUploadChoice);
$('#file-picker').addEventListener('change', async (event) => {
  await uploadFiles([...event.target.files]);
  event.target.value = '';
});
$('#folder-picker').addEventListener('change', async (event) => {
  await uploadFiles([...event.target.files]);
  event.target.value = '';
});

async function uploadFiles(files) {
  if (!files.length) return;
  const status = $('#upload-status');
  status.classList.remove('hidden');
  const baseFolderId = state.mode === 'folder' ? state.folderId : null;
  const createdFolders = new Map();
  for (const file of files) {
    const relativePath = file.webkitRelativePath || '';
    const pathParts = relativePath ? relativePath.split('/') : [];
    if (pathParts.some((part) => !part || part === '.' || part === '..')) {
      toast(`${file.name}: Invalid folder path`, true);
      continue;
    }
    const folderParts = pathParts.slice(0, -1);
    const displayName = relativePath || file.name;
    const line = document.createElement('div');
    line.textContent = `Uploading ${displayName}…`;
    const progress = document.createElement('progress');
    progress.max = 100;
    progress.value = 0;
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'button secondary cancel-upload';
    cancel.textContent = 'Cancel';
    cancel.onclick = () => state.currentUploadRequest?.abort();
    status.replaceChildren(line, progress, cancel);
    try {
      let uploadFolderId = baseFolderId;
      const currentPath = [];
      for (const folderName of folderParts) {
        currentPath.push(folderName);
        const cacheKey = currentPath.join('/');
        if (createdFolders.has(cacheKey)) {
          uploadFolderId = createdFolders.get(cacheKey);
        } else {
          const folder = await api('/api/folders', {
            method: 'POST',
            body: JSON.stringify({ name: folderName, parentId: uploadFolderId })
          });
          uploadFolderId = folder.id;
          createdFolders.set(cacheKey, uploadFolderId);
        }
      }
      await new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();
        state.currentUploadRequest = request;
        request.open('POST', '/api/upload');
        request.withCredentials = true;
        request.setRequestHeader('X-CSRF-Token', state.csrf);
        request.upload.onprogress = (event) => {
          if (event.lengthComputable) progress.value = Math.round(event.loaded / event.total * 100);
        };
        request.onload = () => {
          const result = JSON.parse(request.responseText || '{}');
          if (request.status >= 200 && request.status < 300) resolve(result);
          else reject(new Error(result.error || `Upload failed (${request.status})`));
        };
        request.onerror = () => reject(new Error('Network error while uploading'));
        request.onabort = () => reject(new Error('Upload cancelled'));
        const body = new FormData();
        body.append('folderId', uploadFolderId || '');
        body.append('file', file, file.name);
        request.send(body);
      });
      toast(`${displayName} uploaded. Scanning before it becomes available.`);
    } catch (error) { toast(`${displayName}: ${error.message}`, true); }
    finally { state.currentUploadRequest = null; }
  }
  setTimeout(() => status.classList.add('hidden'), 2500);
  await loadCurrent();
  await loadStorage();
}

const fileArea = $('#file-area');
fileArea.addEventListener('dragenter', (event) => { event.preventDefault(); fileArea.classList.add('dragging'); });
fileArea.addEventListener('dragover', (event) => event.preventDefault());
fileArea.addEventListener('dragleave', (event) => {
  if (!fileArea.contains(event.relatedTarget)) fileArea.classList.remove('dragging');
});
fileArea.addEventListener('drop', async (event) => {
  event.preventDefault();
  fileArea.classList.remove('dragging');
  await uploadFiles([...event.dataTransfer.files]);
});

$('#new-folder').addEventListener('click', async () => {
  const name = prompt('Folder name');
  if (!name) return;
  try {
    await api('/api/folders', { method: 'POST', body: JSON.stringify({ name, parentId: state.folderId }) });
    toast('Folder created');
    await loadCurrent();
  } catch (error) { toast(error.message, true); }
});

document.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => {
  if (state.sort === button.dataset.sort) state.sortDirection *= -1;
  else { state.sort = button.dataset.sort; state.sortDirection = 1; }
  renderFiles();
}));
document.querySelectorAll('.view-option').forEach((button) => button.addEventListener('click', () => {
  state.view = button.dataset.view;
  document.querySelectorAll('.view-option').forEach((option) => option.classList.toggle('selected', option === button));
  renderFiles();
}));

$('#file-list').addEventListener('click', handleAction);
$('#grid-list').addEventListener('click', handleAction);
$('#file-list').addEventListener('change', handleSelection);
$('#grid-list').addEventListener('change', handleSelection);
$('#select-all').addEventListener('change', (event) => {
  const removable = state.files.filter((file) => file.permissions?.canRemove);
  state.selectedIds = event.target.checked ? new Set(removable.map((file) => file.id)) : new Set();
  renderFiles();
});
$('#empty-trash')?.addEventListener('click', emptyTrash);
document.querySelector('.heading-actions').addEventListener('click', (event) => {
  if (event.target.id === 'empty-trash') emptyTrash();
});

async function handleAction(event) {
  if (event.target.matches('.select-file')) return;
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const { action, id: itemId } = target.dataset;
  const file = state.files.find((entry) => entry.id === itemId);
  const folder = state.folders.find((entry) => entry.id === itemId);
  try {
    if (action === 'open-folder') return openFolder(itemId, folder?.isSharedRoot);
    if (action === 'share-file') return openShareDialog('file', file);
    if (action === 'share-folder') return openShareDialog('folder', folder);
    if (action === 'move-file') return openMoveDialog('file', file);
    if (action === 'move-folder') return openMoveDialog('folder', folder);
    if (action === 'download') {
      const link = document.createElement('a');
      link.href = `/api/files/${encodeURIComponent(itemId)}/download`;
      link.download = file?.name || '';
      document.body.append(link);
      link.click();
      link.remove();
    } else if (action === 'star') {
      await api(`/api/files/${itemId}`, { method: 'PATCH', body: JSON.stringify({ starred: !file.starred }) });
      await loadCurrent();
    } else if (action === 'trash') {
      if (!confirm(`Move “${file.name}” to Trash?`)) return;
      await api(`/api/files/${itemId}`, { method: 'DELETE' });
      toast('Moved to Trash');
      await loadCurrent();
      await loadStorage();
    } else if (action === 'purge') {
      if (!confirm(`Permanently delete “${file.name}”? This cannot be undone.`)) return;
      await api(`/api/files/${itemId}?permanent=true`, { method: 'DELETE' });
      await loadCurrent();
      await loadStorage();
    } else if (action === 'restore') {
      await api(`/api/files/${itemId}/restore`, { method: 'POST', body: '{}' });
      toast('File restored');
      await loadCurrent();
    } else if (action === 'edit') {
      await openEditor(file);
    } else if (action === 'rename-folder') {
      const name = prompt('New folder name', folder.name);
      if (!name || name === folder.name) return;
      await api(`/api/folders/${itemId}`, { method: 'PATCH', body: JSON.stringify({ name }) });
      await loadCurrent();
    } else if (action === 'delete-folder') {
      if (!confirm(`Move folder “${folder.name}” and its contents to Trash?`)) return;
      await api(`/api/folders/${itemId}`, { method: 'DELETE' });
      toast('Folder moved to Trash');
      await loadCurrent();
      await loadStorage();
    }
  } catch (error) { toast(error.message, true); }
}

function handleSelection(event) {
  if (!event.target.matches('.select-file')) return;
  const fileId = event.target.dataset.id;
  if (event.target.checked) state.selectedIds.add(fileId);
  else state.selectedIds.delete(fileId);
  renderFiles();
}

$('#bulk-trash').addEventListener('click', async () => {
  if (!state.selectedIds.size || !confirm(`Move ${state.selectedIds.size} selected files to Trash?`)) return;
  try {
    await api('/api/files/bulk-trash', {
      method: 'POST',
      body: JSON.stringify({ ids: [...state.selectedIds] })
    });
    state.selectedIds.clear();
    toast('Selected files moved to Trash');
    await loadCurrent();
    await loadStorage();
  } catch (error) { toast(error.message, true); }
});

let movingItem = null;
async function openMoveDialog(kind, item) {
  const result = await api('/api/folders/all');
  const ownerId = item.ownerId;
  const choices = result.folders.filter((folder) => {
    if (ownerId && folder.ownerId !== ownerId) return false;
    if (kind === 'folder') {
      if (folder.id === item.id) return false;
      let parent = folder.parentId;
      while (parent) {
        if (parent === item.id) return false;
        parent = result.folders.find((candidate) => candidate.id === parent)?.parentId || null;
      }
    }
    return true;
  });
  const select = $('#move-destination');
  select.replaceChildren();
  const rootOption = document.createElement('option');
  rootOption.value = '';
  rootOption.textContent = 'My files (root)';
  select.append(rootOption);
  for (const folder of choices) {
    const option = document.createElement('option');
    option.value = folder.id;
    option.textContent = folder.path;
    select.append(option);
  }
  movingItem = { kind, id: item.id, oldParentId: item.parentId ?? item.folderId ?? null };
  select.value = movingItem.oldParentId || '';
  $('#move-title').textContent = `Move ${kind === 'folder' ? 'folder' : 'file'}: ${item.name}`;
  $('#move-dialog').classList.remove('hidden');
}

function closeMoveDialog() {
  $('#move-dialog').classList.add('hidden');
  movingItem = null;
}
$('#move-close').addEventListener('click', closeMoveDialog);
$('#move-cancel').addEventListener('click', closeMoveDialog);
$('#move-confirm').addEventListener('click', async () => {
  if (!movingItem) return;
  const destination = $('#move-destination').value || null;
  const { kind, id: itemId } = movingItem;
  try {
    if (kind === 'file') {
      await api(`/api/files/${itemId}`, { method: 'PATCH', body: JSON.stringify({ folderId: destination }) });
    } else {
      await api(`/api/folders/${itemId}`, { method: 'PATCH', body: JSON.stringify({ parentId: destination }) });
    }
    closeMoveDialog();
    toast('Item moved');
    await loadCurrent();
  } catch (error) { toast(error.message, true); }
});

function permissionSummary(permissions) {
  const labels = ['Read'];
  if (permissions.canAdd) labels.push('Add');
  if (permissions.canRemove) labels.push('Remove');
  if (permissions.canEdit) labels.push('Edit');
  return labels.join(' · ');
}

async function loadShareList() {
  if (!state.sharing) return;
  const container = $('#share-list');
  container.replaceChildren();
  const result = await api(`/api/shares/${state.sharing.type}/${state.sharing.id}`);
  state.sharing.shares = result.shares;
  if (!result.shares.length) {
    const empty = document.createElement('p');
    empty.className = 'muted share-empty';
    empty.textContent = 'No one else has access.';
    container.append(empty);
    return;
  }
  for (const share of result.shares) {
    const row = document.createElement('div');
    row.className = 'share-list-row';
    const person = document.createElement('div');
    const username = document.createElement('strong');
    username.textContent = share.username;
    const access = document.createElement('span');
    access.className = 'muted';
    access.textContent = permissionSummary(share.permissions);
    person.append(username, access);
    const revoke = document.createElement('button');
    revoke.className = 'button secondary revoke-share';
    revoke.type = 'button';
    revoke.textContent = 'Remove access';
    revoke.addEventListener('click', async () => {
      try {
        await api(`/api/shares/${share.id}`, { method: 'DELETE' });
        toast(`Removed ${share.username}'s access`);
        await loadShareList();
      } catch (error) { toast(error.message, true); }
    });
    row.append(person, revoke);
    container.append(row);
  }
}

async function openShareDialog(type, item) {
  state.sharing = { type, id: item.id, name: item.name, selectedUser: null };
  $('#share-title').textContent = `Share “${item.name}”`;
  $('#share-user-search').value = '';
  $('#share-search-results').replaceChildren();
  $('#share-selected-user').classList.add('hidden');
  $('#share-permissions').classList.add('hidden');
  $('#share-save').disabled = true;
  $('#share-can-add').checked = false;
  $('#share-can-remove').checked = false;
  $('#share-can-edit').checked = false;
  document.querySelectorAll('.share-add-option').forEach((label) => {
    label.classList.toggle('hidden', type !== 'folder');
  });
  $('#share-owner-note').textContent = type === 'folder'
    ? 'New items belong to you and use your storage.'
    : 'This file remains yours and uses your storage.';
  $('#share-dialog').classList.remove('hidden');
  try { await loadShareList(); }
  catch (error) { toast(error.message, true); }
}

function chooseShareUser(username) {
  if (!state.sharing) return;
  state.sharing.selectedUser = username;
  const existing = state.sharing.shares?.find((share) => share.username.toLowerCase() === username.toLowerCase());
  $('#share-can-add').checked = Boolean(existing?.permissions.canAdd);
  $('#share-can-remove').checked = Boolean(existing?.permissions.canRemove);
  $('#share-can-edit').checked = Boolean(existing?.permissions.canEdit);
  $('#share-selected-user').textContent = `Sharing with ${username}`;
  $('#share-selected-user').classList.remove('hidden');
  $('#share-permissions').classList.remove('hidden');
  $('#share-save').disabled = false;
}

$('#share-user-search').addEventListener('input', () => {
  clearTimeout(state.shareSearchTimer);
  state.sharing && (state.sharing.selectedUser = null);
  $('#share-selected-user').classList.add('hidden');
  $('#share-permissions').classList.add('hidden');
  $('#share-save').disabled = true;
  $('#share-can-add').checked = false;
  $('#share-can-remove').checked = false;
  $('#share-can-edit').checked = false;
  const query = $('#share-user-search').value.trim();
  if (query.length < 1) {
    $('#share-search-results').replaceChildren();
    return;
  }
  state.shareSearchTimer = setTimeout(async () => {
    try {
      const result = await api(`/api/users/search?q=${encodeURIComponent(query)}`);
      const container = $('#share-search-results');
      container.replaceChildren();
      if (!result.users.length) {
        const empty = document.createElement('p');
        empty.className = 'muted share-empty';
        empty.textContent = 'No matching registered users.';
        container.append(empty);
      }
      for (const user of result.users) {
        const option = document.createElement('button');
        option.type = 'button';
        option.className = 'share-search-option';
        option.textContent = user.username;
        option.addEventListener('click', () => chooseShareUser(user.username));
        container.append(option);
      }
    } catch (error) { toast(error.message, true); }
  }, 180);
});

$('#share-save').addEventListener('click', async () => {
  if (!state.sharing?.selectedUser) return;
  const { type, id: itemId, selectedUser } = state.sharing;
  const permissions = {
    canAdd: type === 'folder' && $('#share-can-add').checked,
    canRemove: $('#share-can-remove').checked,
    canEdit: $('#share-can-edit').checked
  };
  const button = $('#share-save');
  button.disabled = true;
  try {
    await api(`/api/shares/${type}/${itemId}`, {
      method: 'POST',
      body: JSON.stringify({ username: selectedUser, permissions })
    });
    toast(`Shared with ${selectedUser}`);
    $('#share-user-search').value = '';
    $('#share-search-results').replaceChildren();
    $('#share-selected-user').classList.add('hidden');
    $('#share-permissions').classList.add('hidden');
    state.sharing.selectedUser = null;
    $('#share-can-add').checked = false;
    $('#share-can-remove').checked = false;
    $('#share-can-edit').checked = false;
    await loadShareList();
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = !state.sharing?.selectedUser; }
});

function closeShareDialog() {
  $('#share-dialog').classList.add('hidden');
  state.sharing = null;
}
$('#share-close').addEventListener('click', closeShareDialog);
$('#share-cancel').addEventListener('click', closeShareDialog);

async function emptyTrash() {
  if (!confirm('Permanently delete everything in Trash? This cannot be undone.')) return;
  try {
    await api('/api/trash/empty', { method: 'POST', body: '{}' });
    toast('Trash emptied');
    await loadCurrent();
    await loadStorage();
  } catch (error) { toast(error.message, true); }
}

async function openEditor(file) {
  const result = await api(`/api/files/${file.id}/content`);
  state.editing = file;
  state.originalContent = result.content;
  $('#editor-title').textContent = result.name;
  $('#editor-content').value = result.content;
  $('#editor-message').textContent = 'Changes are rescanned before becoming available.';
  $('#editor').classList.remove('hidden');
}

function closeEditor() {
  if ($('#editor-content').value !== state.originalContent && !confirm('Discard unsaved changes?')) return;
  $('#editor').classList.add('hidden');
  state.editing = null;
}
$('#editor-close').addEventListener('click', closeEditor);
$('#editor-cancel').addEventListener('click', closeEditor);
$('#editor-save').addEventListener('click', async () => {
  if (!state.editing) return;
  const button = $('#editor-save');
  button.disabled = true;
  try {
    await api(`/api/files/${state.editing.id}/content`, {
      method: 'PUT',
      body: JSON.stringify({ content: $('#editor-content').value })
    });
    state.originalContent = $('#editor-content').value;
    $('#editor').classList.add('hidden');
    state.editing = null;
    toast('Saved. The updated file will be available after scanning.');
    await loadCurrent();
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
window.addEventListener('beforeunload', (event) => {
  if (state.editing && $('#editor-content').value !== state.originalContent) {
    event.preventDefault();
    event.returnValue = '';
  }
});

$('#profile-button').addEventListener('click', () => $('#profile-menu').classList.toggle('hidden'));
document.addEventListener('click', (event) => {
  if (!event.target.closest('.topbar-actions')) $('#profile-menu').classList.add('hidden');
});
$('#logout-button').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
  catch (error) { toast(error.message, true); }
  showAuth();
});

async function loadOtpSettings() {
  const result = await api('/api/auth/otp');
  $('#otp-status').textContent = result.enabled
    ? 'Authenticator verification is on. Use your authenticator app when signing in.'
    : 'Authenticator verification is off.';
  $('#otp-disabled-actions').classList.toggle('hidden', result.enabled);
  $('#otp-enabled-actions').classList.toggle('hidden', !result.enabled);
  $('#otp-rotate-code').value = '';
  $('#otp-disable-code').value = '';
}

function clearOtpEnrollment() {
  $('#otp-enrollment').classList.add('hidden');
  $('#otp-settings').classList.remove('hidden');
  $('#otp-qr').removeAttribute('src');
  $('#otp-secret').textContent = '';
  $('#otp-confirm-code').value = '';
}

async function beginOtpSetup(rotation) {
  const button = rotation ? $('#otp-rotate') : $('#otp-enable');
  button.disabled = true;
  try {
    const code = rotation ? $('#otp-rotate-code').value : undefined;
    const result = await api('/api/auth/otp/setup', {
      method: 'POST',
      body: JSON.stringify(code ? { code } : {})
    });
    $('#otp-settings').classList.add('hidden');
    $('#otp-enrollment').classList.remove('hidden');
    $('#otp-enrollment-instructions').textContent = rotation
      ? 'Scan this new QR code with your authenticator app and confirm it with a code from the new setup. Your existing authenticator remains active until confirmation.'
      : 'Scan this QR code with your authenticator app, or enter the secret manually. The secret will not be shown again after confirmation.';
    $('#otp-qr').src = result.qrCode;
    $('#otp-secret').textContent = result.secret;
    $('#otp-confirm-code').focus();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

$('#settings-button').addEventListener('click', async () => {
  $('#profile-menu').classList.add('hidden');
  clearOtpEnrollment();
  $('#settings-dialog').classList.remove('hidden');
  try { await loadOtpSettings(); }
  catch (error) { toast(error.message, true); }
});
$('#settings-close').addEventListener('click', () => {
  clearOtpEnrollment();
  $('#settings-dialog').classList.add('hidden');
});
$('#otp-enable').addEventListener('click', () => beginOtpSetup(false));
$('#otp-rotate').addEventListener('click', () => beginOtpSetup(true));
$('#otp-enrollment-cancel').addEventListener('click', async () => {
  clearOtpEnrollment();
  try { await loadOtpSettings(); }
  catch (error) { toast(error.message, true); }
});
$('#otp-confirm').addEventListener('click', async () => {
  const button = $('#otp-confirm');
  button.disabled = true;
  try {
    await api('/api/auth/otp/confirm', {
      method: 'POST',
      body: JSON.stringify({ code: $('#otp-confirm-code').value })
    });
    clearOtpEnrollment();
    await loadOtpSettings();
    toast('Authenticator verification is enabled.');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});
$('#otp-disable').addEventListener('click', async () => {
  const button = $('#otp-disable');
  button.disabled = true;
  try {
    await api('/api/auth/otp/disable', {
      method: 'POST',
      body: JSON.stringify({ code: $('#otp-disable-code').value })
    });
    await loadOtpSettings();
    toast('Authenticator verification is off.');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});

function closeDeleteAccountDialog() {
  $('#delete-account-dialog').classList.add('hidden');
  $('#delete-account-password').value = '';
  $('#delete-account-code').value = '';
}

$('#delete-account-button').addEventListener('click', async () => {
  $('#profile-menu').classList.add('hidden');
  $('#delete-account-dialog').classList.remove('hidden');
  const button = $('#delete-account-confirm');
  button.disabled = true;
  let settingsLoaded = false;
  try {
    const result = await api('/api/auth/otp');
    $('#delete-account-otp').classList.toggle('hidden', !result.enabled);
    $('#delete-account-code').required = result.enabled;
    settingsLoaded = true;
    (result.enabled ? $('#delete-account-code') : $('#delete-account-password')).focus();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = !settingsLoaded;
  }
});
$('#delete-account-close').addEventListener('click', closeDeleteAccountDialog);
$('#delete-account-cancel').addEventListener('click', closeDeleteAccountDialog);
$('#delete-account-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#delete-account-confirm');
  button.disabled = true;
  try {
    await api('/api/auth/delete', {
      method: 'POST',
      body: JSON.stringify({
        password: $('#delete-account-password').value,
        code: $('#delete-account-code').value
      })
    });
    closeDeleteAccountDialog();
    showAuth();
    toast('Your account has been deleted.');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});

const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark') document.documentElement.dataset.theme = 'dark';
function updateThemeButton() {
  const isDark = document.documentElement.dataset.theme === 'dark';
  const toggle = $('#theme-toggle');
  toggle.querySelector('use').setAttribute('href', `#icon-${isDark ? 'sun' : 'moon'}`);
  const label = `Switch to ${isDark ? 'light' : 'dark'} theme`;
  toggle.setAttribute('aria-label', label);
  toggle.title = label;
}
updateThemeButton();
$('#theme-toggle').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  localStorage.setItem('theme', dark ? 'dark' : 'light');
  updateThemeButton();
});

setAuthMode('login');
trySession();
