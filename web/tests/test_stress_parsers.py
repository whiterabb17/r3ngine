import unittest
from reNgine.parsers import K6Parser, WrkParser, Hping3Parser, LocustParser, TAStressorParser

class StressParsersTest(unittest.TestCase):
    """
    Unit tests to verify the metric parsing and final summary metrics extraction
    for all five supported load testing parsers in the reNgine ecosystem.
    """

    def test_k6_parser(self):
        """
        Verify that K6Parser correctly parses intermediate execution lines
        and extracts final overall metrics like requests, success/fail rate, RPS, and latencies.
        """
        parser = K6Parser()
        
        # Test progress line parsing (running)
        metrics = parser.parse_line("running (00m10.0s), 3/3 VUs, 150 complete")
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics["current_vus"], 3)
        self.assertEqual(metrics["total_requests"], 150)
        self.assertAlmostEqual(metrics["throughput_rps"], 15.0)

        # Test progress line parsing (execution)
        metrics = parser.parse_line("     execution: 00m20.0s / 00m30.0s, 5/5 VUs, 400 complete")
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics["current_vus"], 5)
        self.assertEqual(metrics["total_requests"], 400)
        self.assertAlmostEqual(metrics["throughput_rps"], 20.0)

        # Feed k6 output lines
        parser.parse_line("http_reqs..................: 1500    49.998334/s")
        parser.parse_line("http_req_duration..........: avg=12.5ms min=1.1ms med=10.2ms max=150.3ms p(90)=20.1ms p(95)=25.4ms p(99)=30.5ms")
        
        metrics = parser.get_final_metrics()
        
        self.assertEqual(metrics["total_requests"], 1500)
        self.assertEqual(metrics["successful_requests"], 1500)
        self.assertEqual(metrics["failed_requests"], 0)
        self.assertAlmostEqual(metrics["avg_latency_ms"], 12.5)
        self.assertAlmostEqual(metrics["p95_latency_ms"], 25.4)
        self.assertAlmostEqual(metrics["p99_latency_ms"], 30.5)
        self.assertAlmostEqual(metrics["max_requests_per_second"], 49.998334)

    def test_wrk_parser(self):
        """
        Verify that WrkParser correctly parses throughput and latency summaries,
        including percentile lines, to extract final aggregated metrics.
        """
        parser = WrkParser()
        
        # Feed wrk output lines
        parser.parse_line("  Latency    12.45ms    2.34ms  120.50ms     90.1%")
        parser.parse_line("  Req/Sec     50.23     10.50   100.00       85.2%")
        parser.parse_line("  1500 requests in 30.01s, 2.50MB read")
        parser.parse_line("  Socket errors: connect 0, read 10, write 0, timeout 5")
        parser.parse_line(" 95%    22.50ms")
        parser.parse_line(" 99%    35.10ms")
        parser.parse_line("Requests/sec:    50.23")
        
        metrics = parser.get_final_metrics()
        
        self.assertEqual(metrics["total_requests"], 1500)
        self.assertEqual(metrics["successful_requests"], 1485) # 1500 - (10 read + 5 timeout)
        self.assertEqual(metrics["failed_requests"], 15)
        self.assertAlmostEqual(metrics["avg_latency_ms"], 12.45)
        self.assertAlmostEqual(metrics["p95_latency_ms"], 22.50)
        self.assertAlmostEqual(metrics["p99_latency_ms"], 35.10)
        self.assertAlmostEqual(metrics["max_requests_per_second"], 50.23)

    def test_hping3_parser(self):
        """
        Verify that Hping3Parser correctly parses ping responses and overall packet summaries
        to extract total, successful, failed requests, and RTT/latency metrics.
        """
        parser = Hping3Parser()
        
        # Feed hping3 output lines
        parser.parse_line("len=46 ip=192.168.1.1 ttl=64 id=123 sport=80 flags=SA seq=0 win=512 rtt=12.3 ms")
        parser.parse_line("len=46 ip=192.168.1.1 ttl=64 id=124 sport=80 flags=SA seq=1 win=512 rtt=15.6 ms")
        parser.parse_line("len=46 ip=192.168.1.1 ttl=64 id=125 sport=80 flags=SA seq=2 win=512 rtt=9.4 ms")
        parser.parse_line("--- example.txt hping statistic ---")
        parser.parse_line("5 packets transmitted, 3 packets received, 40% packet loss")
        parser.parse_line("round-trip min/avg/max = 9.4/12.43/15.6 ms")
        
        metrics = parser.get_final_metrics()
        
        self.assertEqual(metrics["total_requests"], 5)
        self.assertEqual(metrics["successful_requests"], 3)
        self.assertEqual(metrics["failed_requests"], 2)
        self.assertAlmostEqual(metrics["avg_latency_ms"], 12.433333333)
        self.assertAlmostEqual(metrics["p95_latency_ms"], 15.6) # fallback to max in hping3
        self.assertAlmostEqual(metrics["p99_latency_ms"], 15.6) # fallback to max in hping3

    def test_locust_parser(self):
        """
        Verify that LocustParser correctly parses CSV/printed stats output lines
        to aggregate total, successful, failed requests, average latency, and max RPS.
        """
        parser = LocustParser()
        
        # Feed locust output lines
        parser.parse_line(" Name                                                            # reqs      # fails |    Avg     Min     Max    Med |   req/s failures/s")
        parser.parse_line(" GET /                                                             1200     5 (0.4%) |     15       2     150     10 |   45.20    0.10")
        parser.parse_line(" Aggregated                                                        1200     5 (0.4%) |     15       2     150     10 |   45.20    0.10")
        
        metrics = parser.get_final_metrics()
        
        self.assertEqual(metrics["total_requests"], 1200)
        self.assertEqual(metrics["successful_requests"], 1195)
        self.assertEqual(metrics["failed_requests"], 5)
        self.assertAlmostEqual(metrics["avg_latency_ms"], 15.0)
        self.assertAlmostEqual(metrics["max_requests_per_second"], 45.20)

    def test_ta_stressor_parser(self):
        """
        Verify that TAStressorParser correctly parses stdout lines containing BPS, PPS, and PPS_failed metrics
        to extract the final overall request counts and RPS.
        """
        parser = TAStressorParser()
        
        # Feed stressor output lines
        parser.parse_line("[*] Thread-1: Sending payload to target")
        parser.parse_line("PPS: 250 | BPS: 120400 | PPS_failed: 5")
        parser.parse_line("PPS: 300 | BPS: 154000 | PPS_failed: 2")
        
        metrics = parser.get_final_metrics()
        
        self.assertEqual(metrics["total_requests"], 550) # 250 + 300
        self.assertEqual(metrics["failed_requests"], 7)  # 5 + 2
        self.assertEqual(metrics["successful_requests"], 543)
        self.assertAlmostEqual(metrics["max_requests_per_second"], 300.0)

if __name__ == '__main__':
    unittest.main()
