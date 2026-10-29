use ark_bn254::Fr;
use ark_ff::Zero;

use crate::nullifier::hash;

pub(crate) const TREE_DEPTH: usize = 24;
const TREE_ARITY: usize = 2;

/// Nodes past a level's end are empty subtrees.
#[derive(Clone, Debug)]
pub(crate) struct Tree {
    /// Leaves first.
    levels: Vec<Vec<Fr>>,
    empty_roots: Vec<Fr>,
}

impl Tree {
    pub(crate) fn new(leaves: Vec<Fr>) -> Self {
        let empty_roots = empty_subtree_roots();
        let mut levels = Vec::with_capacity(TREE_DEPTH.saturating_add(1));
        let mut nodes = leaves;
        for &fill in empty_roots.iter().take(TREE_DEPTH) {
            let parents = nodes
                .chunks(TREE_ARITY)
                .map(|pair| {
                    let left = pair.first().copied().unwrap_or(fill);
                    let right = pair.get(1).copied().unwrap_or(fill);
                    hash(&[left, right])
                })
                .collect();
            levels.push(nodes);
            nodes = parents;
        }
        levels.push(nodes);
        Self { levels, empty_roots }
    }

    pub(crate) fn root(&self) -> Fr {
        self.node(TREE_DEPTH, 0)
    }

    pub(crate) fn leaf(&self, slot: usize) -> Fr {
        self.node(0, slot)
    }

    pub(crate) fn path(&self, slot: usize) -> Vec<Fr> {
        let mut index = slot;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            siblings.push(self.node(level, index ^ 1));
            index >>= 1;
        }
        siblings
    }

    /// `slot < 2^TREE_DEPTH`.
    pub(crate) fn set(&mut self, slot: usize, leaf: Fr) {
        let mut index = slot;
        let mut node = leaf;
        for level in 0..=TREE_DEPTH {
            let fill = self.empty_roots.get(level).copied().unwrap_or_else(Fr::zero);
            if let Some(nodes) = self.levels.get_mut(level) {
                if nodes.len() <= index {
                    nodes.resize(index.saturating_add(1), fill);
                }
                if let Some(n) = nodes.get_mut(index) {
                    *n = node;
                }
            }
            let sibling = self.node(level, index ^ 1);
            node = if index & 1 == 0 { hash(&[node, sibling]) } else { hash(&[sibling, node]) };
            index >>= 1;
        }
    }

    fn node(&self, level: usize, index: usize) -> Fr {
        self.levels
            .get(level)
            .and_then(|nodes| nodes.get(index))
            .or_else(|| self.empty_roots.get(level))
            .copied()
            .unwrap_or_else(Fr::zero)
    }
}

pub(crate) fn root_of(slot: usize, leaf: Fr, siblings: &[Fr]) -> Fr {
    let mut index = slot;
    let mut node = leaf;
    for &sibling in siblings {
        node = if index & 1 == 0 { hash(&[node, sibling]) } else { hash(&[sibling, node]) };
        index >>= 1;
    }
    node
}

fn empty_subtree_roots() -> Vec<Fr> {
    let mut node = Fr::zero();
    (0..=TREE_DEPTH)
        .map(|_| {
            let this = node;
            node = hash(&[node, node]);
            this
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;

    use super::{TREE_DEPTH, Tree, empty_subtree_roots, root_of};
    use crate::nullifier::hash;

    fn leaves(n: u64) -> Vec<Fr> {
        (1..=n).map(Fr::from).collect()
    }

    #[test]
    fn root_hashes_up_from_the_leaves() {
        let [a, b, c] = [1u8, 2, 3].map(Fr::from);
        let empty = empty_subtree_roots();
        let mut node = hash(&[hash(&[a, b]), hash(&[c, Fr::zero()])]);
        for &e in empty.iter().skip(2).take(TREE_DEPTH - 2) {
            node = hash(&[node, e]);
        }
        assert_eq!(Tree::new(vec![a, b, c]).root(), node);
        assert_eq!(Some(Tree::new(Vec::new()).root()), empty.get(TREE_DEPTH).copied());
    }

    #[test]
    fn set_matches_a_rebuild() {
        let mut tree = Tree::new(leaves(5));
        let mut expected = leaves(5);
        for (slot, leaf) in [(2, 9u8), (0, 0), (7, 4), (4, 0), (12, 5)] {
            tree.set(slot, Fr::from(leaf));
            if expected.len() <= slot {
                expected.resize(slot + 1, Fr::zero());
            }
            if let Some(e) = expected.get_mut(slot) {
                *e = Fr::from(leaf);
            }
            assert_eq!(tree.root(), Tree::new(expected.clone()).root(), "after setting slot {slot}");
        }
    }

    #[test]
    fn path_gives_the_root() {
        let tree = Tree::new(leaves(6));
        for slot in [0, 3, 5, 6, 1000] {
            let path = tree.path(slot);
            assert_eq!(path.len(), TREE_DEPTH);
            assert_eq!(root_of(slot, tree.leaf(slot), &path), tree.root());
        }
    }
}
