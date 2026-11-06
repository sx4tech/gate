import unittest
from unittest.mock import patch
import performance as p
import vpngate as gate


class QualityTests(unittest.TestCase):
    def test_slower_sample_controls_admission(self):
        samples = [{'ok': True, 'download_mbps': 30, 'ttfb_ms': 100},
                   {'ok': True, 'download_mbps': 3, 'ttfb_ms': 130}]
        self.assertEqual(p.summarize_samples(samples)['download_mbps'], 3)
        self.assertIsNone(p.summarize_samples([samples[0], {'ok': False}]))

    def test_low_throughput_exit_is_excluded(self):
        nodes = [dict(host='fast.opengw.net', port=443, success=True, latency_ms=2000,
                      country_code='JP', country='Japan', residential='residential'),
                 dict(host='slow.opengw.net', port=443, success=True, latency_ms=1000,
                      country_code='JP', country='Japan', residential='residential')]
        def fake(mode, host, port, **kw):
            return {'ok': True, 'download_mbps': 2 if host.startswith('slow') else 25,
                    'ttfb_ms': 120, 'download_bytes': 2097152}
        with patch.dict('os.environ', {'EXIT_MIN_MBPS': '10'}):
            selected, records = p.select_exits(nodes, fake)
        self.assertEqual([x['host'] for x in selected], ['fast.opengw.net'])
        self.assertEqual(len(records), 2)

    def test_country_limit_and_global_limit(self):
        nodes = [dict(host=f'vpn{i}.opengw.net', port=443, success=True, latency_ms=100,
                      country_code='JP' if i < 6 else 'KR') for i in range(12)]
        fake = lambda *a, **k: {'ok': True, 'download_mbps': 20, 'ttfb_ms': 100}
        selected, _ = p.select_exits(nodes, fake)
        self.assertEqual(len(selected), 6)
        self.assertEqual(sum(n['country_code'] == 'JP' for n in selected), 3)

    def test_empty_selection_does_not_fall_back_to_reachable_nodes(self):
        result = [dict(host='slow.opengw.net', success=True)]
        data = gate.build_outputs(result, 1, 1, 'fixture', selected=[])
        self.assertEqual(data['available'], [])
        self.assertEqual(data['stats']['reachable'], 1)
        self.assertEqual(data['stats']['success'], 0)
        self.assertEqual(gate.build_nodes_text(data, []), '')

    def test_output_contains_only_measured_entries_and_exits(self):
        node = dict(host='vpn1.opengw.net', port=443, country_code='JP',
                    residential='residential', performance={'download_mbps': 25})
        text = gate.build_nodes_text({'available': [node]}, ['104.16.1.1:443'])
        self.assertEqual(text, '104.16.1.1:443#日本-住宅-01-25Mbps$sstp://vpn:vpn@vpn1.opengw.net:443\n')

    def test_unstable_entry_is_rejected_without_speed_test(self):
        calls = []
        def fake(mode, *a, **kw):
            calls.append(mode)
            return {'ok': len(calls) != 2, 'latency_ms': 50, 'colo': 'IAD'}
        with patch.object(p, 'resolve_entries', return_value=[('104.16.1.1', 443)]):
            chosen, records = p.measure_entries([], 'example.com', fake)
        self.assertEqual(chosen, [])
        self.assertEqual(calls, ['entry-latency'] * 3)
        self.assertIn('rejection', records[0])

if __name__ == '__main__':
    unittest.main()
