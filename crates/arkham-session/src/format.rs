use arkham_config::config::RewriteFormat;

/// The format an unstated rewrite probes as, if any. Kubeconfig first: its
/// markers are the more specific pair.
#[must_use]
pub(crate) fn sniff(content: &[u8]) -> Option<RewriteFormat> {
  let text = String::from_utf8_lossy(content);
  if text.contains("current-context:") && text.contains("clusters:") {
    return Some(RewriteFormat::Kubeconfig);
  }
  if text.contains("contexts:") && text.contains("endpoints:") {
    return Some(RewriteFormat::Talos);
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sniff_picks_kubeconfig_over_talos_on_shared_markers() {
    assert_eq!(
      sniff(b"context: c\ncontexts:\n  c:\n    endpoints:\n      - 10.0.0.1\n"),
      Some(RewriteFormat::Talos)
    );
    assert_eq!(
      sniff(b"current-context: c\nclusters:\n- name: c\n"),
      Some(RewriteFormat::Kubeconfig)
    );
    assert_eq!(sniff(b"just a file\n"), None);
  }
}
