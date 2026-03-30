# Relationship Decision Matrix
# Golden Logic — Knowledge Relationship Classification Engine
# Version: 1.0.0 | DNS Tool 26.35.20

The three spatial positions in a knowledge graph carry exact semantic meaning.
This matrix eliminates ambiguity when classifying any relationship between two entities.

## The Three Positions

| Position | Relation | Semantic Meaning |
|----------|----------|------------------|
| BELOW    | child    | Owned by, created by, component of, would not exist without parent |
| ABOVE    | parent   | Contains, has authority over, owns the child |
| LEFT     | jump     | Related but independent — neither owns the other |

## The Decision Sequence

For any two entities A and B, ask in this exact order:

### Step 1 — Ownership Test (determines child/parent)

Ask these three questions. If ANY answer is YES, B is a **child** of A:

1. "Did A create B?"
2. "Does A control or maintain B?"
3. "Would B stop existing if A were removed?"

If all three are NO, proceed to Step 2.

### Step 2 — Independence Test (confirms jump)

Ask these two questions. If EITHER answer is YES, B is a **jump** from A:

4. "Does B exist independently of A, but they interact?"
5. "Is B an external entity, system, or concept that A references but does not own?"

### Step 3 — Dual Parentage

If B passes the ownership test for MULTIPLE entities, B has multiple parents.
This is valid. Example: DNS Tool is a child of BOTH Carey (creator) AND IT Help (corporation).
The chain-of-authority model (Carey → IT Help → DNS Tool) is clean but incomplete.
Direct creative ownership is a real relationship that deserves its own link.

## Applied Examples

| Entity A | Entity B | Q1 Create? | Q2 Control? | Q3 Vanish? | Result |
|----------|----------|------------|-------------|------------|--------|
| Carey | Founder's Voice | YES | YES | YES | **child** (below) |
| Carey | Personal OpSec | YES | YES | YES | **child** (below) |
| Carey | DNS Tool | YES | YES | YES | **child** (below) |
| Carey | IT Help San Diego | YES | YES | YES | **child** (below) |
| Carey | ORCID | NO | NO | NO | **jump** (left) — ORCID exists independently |
| Carey | Zenodo | NO | NO | NO | **jump** (left) — Zenodo exists independently |
| IT Help | DNS Tool | YES | YES | YES | **child** (below) |
| IT Help | Operational Security | YES | YES | YES | **child** (below) |
| Operational Security | Personal OpSec | YES | YES | YES | **child** (below) |
| Operational Security | Corporate OpSec | YES | YES | YES | **child** (below) |
| Operational Security | Product OpSec | YES | YES | YES | **child** (below) |
| DNS Tool | Golden Logic | YES | YES | YES | **child** (below) |
| Product OpSec | DNS Tool | NO | NO | NO | **jump** (left) — OpSec is about DNS Tool, doesn't own it |

## The Topology Vision

This decision matrix is not just for TheBrain. It is the classification engine
that powers the DNS Tool topology view. When `mode=logic` is active:

- Nodes are entities (domains, records, policies, authorities)
- Edges are classified by this same ownership test
- CHILD edges show containment and dependency (domain → SPF record)
- JUMP edges show cross-references (SPF → external include)
- Data flows along child edges, references flow along jump edges
- Live animation shows the direction of authority and dependency

The same three questions that organize a founder's knowledge graph
organize the entire DNS security analysis pipeline.

## Codec

This matrix is machine-readable. The Golden Logic engine SHALL implement
these three questions as boolean functions that classify any edge in the
knowledge graph or DNS topology automatically.

```
func ClassifyRelation(a, b Entity) Relation {
    if a.Created(b) || a.Controls(b) || b.VanishesWithout(a) {
        return Child  // BELOW
    }
    if b.ExistsIndependently() || b.IsExternalReference() {
        return Jump   // LEFT
    }
    return Unclassified  // needs human decision
}
```
