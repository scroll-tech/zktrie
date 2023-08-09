use std::error::Error;
use std::fmt::Debug;
use num_derive::FromPrimitive;
use num;

#[derive(Debug, Display)]
pub enum ErrorCode {
    ErrorNodeBytesBadSize,
}

impl Error for ErrorCode {}
const HASH_BYTE_LEN: usize = 32;

pub trait Hashable : Clone + Debug + Default + PartialEq {
    fn hash_elems_with_domain(domain: u64, lbytes: &Option<Self>, rbytes: &Option<Self>) -> Result<Self, ErrorCode>;
    fn handling_elems_and_bytes32(flags: u32, bytes: &Vec<[u8; 32]>) -> Result<Self, ErrorCode>;
    fn hash_from_bytes(bytes: &Vec<u8>) -> Result<Self, ErrorCode>;
    fn hash_zero() -> Self;
}


#[derive (Copy, Clone, Debug, FromPrimitive, Display, PartialEq)]
pub enum NodeType {
	// NodeTypeParent indicates the type of parent Node that has children.
	NodeTypeParent = 0,
	// NodeTypeLeaf indicates the type of a leaf Node that contains a key &
	// value.
	NodeTypeLeaf = 1,
	// NodeTypeEmpty indicates the type of an empty Node.
	NodeTypeEmpty = 2,

	// DBEntryTypeRoot indicates the type of a DB entry that indicates the
	// current Root of a MerkleTree
	DBEntryTypeRoot = 3,

	NodeTypeLeafNew = 4,
	NodeTypeEmptyNew = 5,
	// branch node for both child are terminal nodes
	NodeTypeBranch0 = 6,
	// branch node for left child is terminal node and right child is branch
	NodeTypeBranch1 = 7,
	// branch node for left child is branch node and right child is terminal
	NodeTypeBranch2 = 8,
	// branch node for both child are branch nodes
	NodeTypeBranch3 = 9,
}

use NodeType::*;
use strum_macros::Display;

impl NodeType {
    /// deduce a new branch type from current branch when one of its child become non trivial
    pub fn deduce_upgrade_type(&self, is_right: bool) -> Self {
        if is_right {
            match self {
                NodeTypeBranch0 => NodeTypeBranch1,
                NodeTypeBranch1 => self.clone(),
                NodeTypeBranch2 => NodeTypeBranch3,
                _ => unreachable!(),
            }
        } else {
            match self {
                NodeTypeBranch0 => NodeTypeBranch2,
                NodeTypeBranch1 => NodeTypeBranch3,
                NodeTypeBranch3 => NodeTypeBranch3,
                NodeTypeBranch2 => self.clone(),
                _ => unreachable!(),
		    }
        }
    }


    /// deduce a new branch type from current branch when one of its child become terminal
    pub fn deduce_downgrade_type(&self, is_right: bool) -> Self {
        if is_right {
            match self {
                NodeTypeBranch1 => NodeTypeBranch0,
                NodeTypeBranch3 => NodeTypeBranch2,
                _ => {
                    panic!("can not downgrade a node with terminal child {}", self);
                }
            }
        } else {
            match self {
                NodeTypeBranch3 => NodeTypeBranch1,
                NodeTypeBranch2 => NodeTypeBranch0,
                _ => {
                    panic!("can not downgrade a node with terminal child {}", self);
                }
		    }
        }
    }
}

// Node is the struct that represents a node in the MT. The node should not be
// modified after creation because the cached key won't be updated.
pub struct Node<H: Hashable> {
	// node_type is the type of node in the tree.
	pub node_type: NodeType,
	// child_l is the node hash of the left child of a parent node.
    pub child_left: Option<H>,
	// child_r is the node hash of the right child of a parent node.
	pub child_right: Option<H>,
	// key is the node's key stored in a leaf node.
	pub node_key: H,
	// value_preimage can store at most 256 byte32 as fields (represnted by BIG-ENDIAN integer)
	// and the first 24 can be compressed (each bytes32 consider as 2 fields), in hashing the compressed
	// elemments would be calculated first
	value_preimage: Vec<[u8; 32]>,
	// use each bit for indicating the compressed flag for the first 24 fields
	compress_flags: u32,
	// nodeHash is the cache of the hash of the node to avoid recalculating
	pub node_hash: Option<H>,
	// valueHash is the cache of the hash of valuePreimage to avoid recalculating, only valid for leaf node
	value_hash: Option<H>,
	// KeyPreimage is the original key value that derives the node_key, kept here only for proof
	key_preimage: Vec<[u8; 32]>,
}

impl<H: Hashable> Node<H> {
    /// create a new leaf node
    pub fn new_leaf_node(node_key: H, value_flags: u32, value_preimage: Vec<[u8; 32]>) -> Self {
        Node {
	       node_type: NodeType::NodeTypeLeafNew,
           node_key,
           compress_flags: value_flags,
           value_preimage,
           child_left: None,
           child_right: None,
           node_hash: None,
           value_hash: None,
           key_preimage: vec![],
        }
    }

    /// creates a new parent node.
    pub fn new_parent_node(node_type: NodeType, child_left: H, child_right: H) -> Self {
        Node {
	       node_type,
           node_key: H::default(),
           compress_flags: 0,
           value_preimage: vec![],
           child_left: Some(child_left),
           child_right: Some(child_right),
           node_hash: None,
           value_hash: None,
           key_preimage: vec![],
        }
    }

    /// creates a new empty node.
    pub fn new_empty_node() -> Self {
        Node {
	       node_type: NodeType::NodeTypeEmpty,
           node_key: H::default(),
           compress_flags: 0,
           value_preimage: vec![],
           child_left: None,
           child_right: None,
           node_hash: None,
           value_hash: None,
           key_preimage: vec![],
        }
    }

    // new_node_from_bytes creates a new node by parsing the input []byte.
    pub fn new_node_from_bytes(b: Vec<u8>) -> Result<Node<H>, ErrorCode> {
    	if b.len() < 1 {
    		Err(ErrorCode::ErrorNodeBytesBadSize)
    	} else {
            let mut node =  Node::new_empty_node();
    	    node.node_type = num::FromPrimitive::from_u32(b[0] as u32).unwrap();
    	    let b = b[1..].to_vec();
            match node.node_type {
                NodeTypeParent | NodeTypeBranch0 |
                NodeTypeBranch1 |NodeTypeBranch2 | NodeTypeBranch3 => {
                    if b.len() != 2 * HASH_BYTE_LEN {
                    	Err(ErrorCode::ErrorNodeBytesBadSize)
                    } else {
                        node.child_left = Some(H::hash_from_bytes(&b[..HASH_BYTE_LEN].to_vec())?);
                        node.child_right = Some(H::hash_from_bytes(&b[HASH_BYTE_LEN..HASH_BYTE_LEN*2].to_vec())?);
                        Ok(node)
                    }
                },
                _ => Ok(node)

            }
                /*
        	case NodeTypeLeaf, NodeTypeLeaf_New:
        		if len(b) < HASH_BYTE_LEN+4 {
        			return nil, ErrNodeBytesBadSize
        		}
        		n.node_key = H::hash_from_bytes(b[0:HASH_BYTE_LEN])
        		mark := binary.LittleEndian.Uint32(b[HASH_BYTE_LEN : HASH_BYTE_LEN+4])
        		preimageLen := int(mark & 255)
        		n.CompressedFlags = mark >> 8
        		n.ValuePreimage = make([]zkt.Byte32, preimageLen)
        		curPos := HASH_BYTE_LEN + 4
        		if len(b) < curPos+preimageLen*32+1 {
        			return nil, ErrNodeBytesBadSize
        		}
        		for i := 0; i < preimageLen; i++ {
        			copy(n.ValuePreimage[i][:], b[i*32+curPos:(i+1)*32+curPos])
        		}
        		curPos += preimageLen * 32
        		preImageSize := int(b[curPos])
        		curPos += 1
        		if preImageSize != 0 {
        			if len(b) < curPos+preImageSize {
        				return nil, ErrNodeBytesBadSize
        			}
        			n.KeyPreimage = new(zkt.Byte32)
        			copy(n.KeyPreimage[:], b[curPos:curPos+preImageSize])
        		}
        	case NodeTypeEmpty, NodeTypeEmpty_New:
        		break
        	default:
        		return nil, ErrInvalidNodeFound
        	}
            */
        }
    }
    /// is_terminal returns if the node is 'terminated', i.e. empty or leaf node
    pub fn is_terminal(&self) -> bool {
    	match self.node_type {
    	    NodeTypeEmptyNew | NodeTypeLeafNew => true,
    	    NodeTypeBranch0 | NodeTypeBranch1 | NodeTypeBranch2 | NodeTypeBranch3 => false,
    	    NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent => panic!("encounter deprecated node types"),
            _ => panic!("encounter unknown node types {:?}", self.node_type)
    	}
    }

    /// NodeHash computes the hash digest of the node by hashing the content in a
    /// specific way for each type of node.  This key is used as the hash of the
    /// Merkle tree for each node.
    pub fn node_hash(&mut self) -> Result<H, ErrorCode> {
    	if self.node_hash.is_none() { // Cache the key to avoid repeated hash computations.
        // NOTE: We are not using the type to calculate the hash!
            match self.node_type {
                NodeTypeBranch0
                | NodeTypeBranch1
                | NodeTypeBranch2
                | NodeTypeBranch3  => {// H(ChildL || ChildR)
                    self.node_hash = Some(H::hash_elems_with_domain (
                        self.node_type as u64,
                        &self.child_left,
                        &self.child_right,
                    )?);
                },
                NodeTypeLeafNew => {
                	self.value_hash = Some(H::handling_elems_and_bytes32(
                        self.compress_flags,
                        &self.value_preimage
                    )?);
                    self.node_hash = Some(self.leaf_hash(&Some(self.node_key.clone()), &self.value_hash)?);
                },
                NodeTypeEmptyNew => { // Zero
                    self.node_hash = Some(H::hash_zero());
                }
                NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent =>
                	panic!("encounter deprecated node types"),
                _ => self.node_hash = Some(H::hash_zero())
            }
    	}
        Ok(self.node_hash.unwrap())
    }

    /// ValueHash computes the hash digest of the value stored in the leaf node. For
    /// other node types, it returns the zero hash.
    pub fn value_hash(&mut self) -> Result<H, ErrorCode> {
        match self.node_type {
            NodeTypeLeafNew => {
                Ok(H::hash_zero())
            },
            _ => {
                self.node_hash()?;
                Ok(self.value_hash.as_ref().unwrap().clone())
            }
        }
    }

    /// LeafHash computes the key of a leaf node given the hIndex and hValue of the
    /// entry of the leaf.
    pub fn leaf_hash(&self, k: &Option<H>, v: &Option<H>) -> Result<H, ErrorCode> {
        H::hash_elems_with_domain(self.node_type as u64, k, v)
    }

    /// Data returns the wrapped data inside LeafNode and cast them into bytes
    /// for other node type it just return None
    pub fn data(&self) -> Option<Vec<u8>> {
        match self.node_type {
            NodeTypeLeafNew => unsafe {
                let slice = std::slice::from_raw_parts(self.value_preimage.as_ptr() as *const [u8;32], self.value_preimage.len());
                Some(slice.flatten().to_vec())
            },
            _ => None
        }
	}

    // Value returns the encoded bytes of a node, include all information of it
    pub fn value(&self) -> Vec<u8> {
        let mut out_bytes = self.canonical_value();
        let len = out_bytes.len();
        match self.node_type {
            NodeTypeLeafNew => {
                if !self.key_preimage.is_empty() {
			        out_bytes[len-1] = self.key_preimage.len() as u8;
                    let bytes = unsafe { std::slice::from_raw_parts(self.key_preimage.as_ptr() as *const u8, self.key_preimage.len()*32) };
                    out_bytes.append(&mut bytes.to_vec())
                }
            },
            _ => {}
		}
	    out_bytes
	}

    /// CanonicalValue returns the byte form of a node required to be persisted, and strip unnecessary fields
    /// from the encoding (current only KeyPreimage for Leaf node) to keep a minimum size for content being
    /// stored in backend storage
    pub fn canonical_value(&self) -> Vec<u8> {
        todo!();
        /*
        match self.node_type {
        switch n.Type {
    	case NodeTypeBranch_0, NodeTypeBranch_1, NodeTypeBranch_2, NodeTypeBranch_3: // {Type || ChildL || ChildR}
    		bytes := []byte{byte(n.Type)}
    		bytes = append(bytes, n.ChildL.Bytes()...)
    		bytes = append(bytes, n.ChildR.Bytes()...)
    		return bytes
    	case NodeTypeLeaf_New: // {Type || Data...}
    		bytes := []byte{byte(n.Type)}
    		bytes = append(bytes, n.node_key.Bytes()...)
    		tmp := make([]byte, 4)
    		compressedFlag := (n.CompressedFlags << 8) + uint32(len(n.ValuePreimage))
    		binary.LittleEndian.PutUint32(tmp, compressedFlag)
    		bytes = append(bytes, tmp...)
    		for _, elm := range n.ValuePreimage {
    			bytes = append(bytes, elm[:]...)
    		}
    		bytes = append(bytes, 0)
    		return bytes
    	case NodeTypeEmpty_New: // { Type }
    		return []byte{byte(n.Type)}
    	case NodeTypeEmpty, NodeTypeLeaf, NodeTypeParent:
    		panic("encounter deprecated node types")
    	default:
    		return []byte{}
    	}
        */
    }

    /// String outputs a string representation of a node (different for each type).
    pub fn to_tring(&self) -> String {
        match self.node_type {
        // {Type || ChildL || ChildR}
            NodeTypeBranch0 =>
            	format!("Parent L(t):{:?} R(t):{:?}", self.child_left, self.child_right),
            NodeTypeBranch1 =>
            	format!("Parent L(t):{:?} R:{:?}", self.child_left, self.child_right),
            NodeTypeBranch2 =>
            	format!("Parent L:{:?} R(t):{:?}", self.child_left, self.child_right),
            NodeTypeBranch3 =>
            	format!("Parent L:{:?} R:{:?}", self.child_left, self.child_right),
            NodeTypeLeafNew => // {Type || Data...}
            	format!("Leaf I:{:?} Items: {}, First:{:?}",
                        self.node_key,
                        self.value_preimage.len(),
                        self.value_preimage[0]),
            NodeTypeEmptyNew => // {}
            	"Empty".to_string(),
            NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent =>
            	"deprecated Node".to_string(),
            _ => "Invalid Node".to_string()
        }
    }
}

