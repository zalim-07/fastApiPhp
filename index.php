<?php
class CallFilter
{
  private array $whitelist = [];
  private int $threshold = 8;
  private string $csvUrl = 'Here_link_to_your_csv_file';
  private string $apiKey = 'YOUR_API_KEY'; //

  public function __construct()
  {
    $this->whitelist = $this->loadWhitelist();
  }

  private function loadWhitelist(): array
  {
    $csvContent = @file_get_contents($this->csvUrl);
    if ($csvContent === false) {
      error_log("Failed to fetch CSV");
       $csvContent = "PhoneNumber\n0123456789\n1234567980";
    } 

    $lines = explode("\n", $csvContent);
    array_shift($lines);

    $whitelist = [];

    foreach ($lines as $line) {
      $row = str_getcsv($line);
      if (!empty($row[0])) {
        $whitelist[] = trim($row[0]);
      }
    }

    return $whitelist;
  }

  private function checkAuth(): bool
  {
    $headers = getallheaders();
    return isset($headers['Authorization']) && $headers['Authorization'] === 'Bearer ' . $this->apiKey;
  }

  private function logAction(string $identifier, string $action, string $reason): void
  {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $logLine = date('Y-m-d H:i:s') . " | IP: $ip | $identifier | $action | $reason\n";
    file_put_contents(__DIR__ . '/call_filter.log', $logLine, FILE_APPEND);
  }

  public function checkPhone(string $phone, bool $isSpam = false, int $confidence = 0, string $callType = ''): array
  {
    $callType = strtolower($callType);

    if (in_array($phone, $this->whitelist)) {
      return ['action' => 'ALLOW', 'reason' => 'Whitelisted'];
    } elseif ($isSpam && $confidence >= $this->threshold && in_array($callType, ['scam', 'robocall'])) {
      return ['action' => 'BLOCK', 'reason' => 'High confidence spam'];
    } else {
      $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
      $this->logAction("IP: $ip", $phone, 'Low confidence or unknown');
      return ['action' => 'LOG', 'reason' => 'Low confidence or unknown'];
    }
  }

  public function handleRequest(): void
  {
    $requestUri = $_SERVER['REQUEST_URI'];
    $requestMethod = $_SERVER['REQUEST_METHOD'];

    if ($requestUri === '/filter_call' && $requestMethod === 'POST') {
      header('Content-Type: application/json');

      if (!$this->checkAuth()) {
        http_response_code(401);

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        echo json_encode(['error' => 'Unauthorized']);

        $this->logAction("IP: $ip", 'UNAUTHORIZED', 'Invalid API key');
        return;
      }

      $input = json_decode(file_get_contents('php://input'), true);

      if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON']);
        return;
      }

      $phone = $input['PhoneNumber'] ?? '';
      $isSpam = $input['IsSpam'] ?? false;
      $confidence = $input['Confidence'] ?? 0;
      $callType = strtolower($input['CallType'] ?? '');

      $result = $this->checkPhone($phone, $isSpam, $confidence, $callType);

      echo json_encode($result);
      return;
    }

    http_response_code(404);
    echo "Not Found!";
  }
}


$filter = new CallFilter();
$filter->handleRequest();


// $phone = '1234567890';
// $result = $filter->checkPhone($phone, true, 0, 'scam');
