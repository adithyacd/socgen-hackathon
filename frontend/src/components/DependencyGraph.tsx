import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import fcose from "cytoscape-fcose";
import type { AppGraph, GraphNode } from "../api/types";
import { SEVERITY_HEX } from "../lib/risk";

cytoscape.use(fcose);

const APP_HEX = "#F4F4F5";   // the application node is neutral (not a risk)
const LICENSE_HEX = "#79808F";
const CLEAN_HEX = "#33333A";  // faintly visible on pure black
const STALE_HEX = "#5A5A63";

function nodeColor(n: GraphNode): string {
  if (n.kind === "app") return APP_HEX;
  if (n.is_vulnerable && n.severity) return SEVERITY_HEX[n.severity];
  if (n.risk_types.includes("license_conflict")) return LICENSE_HEX;
  if (n.risk_types.includes("unmaintained")) return STALE_HEX;
  return CLEAN_HEX;
}

function nodeSize(n: GraphNode): number {
  if (n.kind === "app") return 52;
  if (n.is_vulnerable) return n.severity === "critical" ? 34 : 28;
  if (n.risk_types.length) return 22;
  return 15;
}

function toElements(graph: AppGraph): ElementDefinition[] {
  const nodes: ElementDefinition[] = graph.nodes.map((n) => ({
    data: {
      id: n.id,
      label: n.kind === "app" ? n.library : n.library,
      color: nodeColor(n),
      size: nodeSize(n),
      kind: n.kind,
      dim: n.is_vulnerable && n.is_reachable === false ? 1 : 0, // unreachable = suppressed
      raw: n,
    },
    classes: n.is_vulnerable && n.is_reachable === false ? "suppressed" : "",
  }));
  const edges: ElementDefinition[] = graph.edges.map((e, i) => ({
    data: {
      id: `e${i}`,
      source: e.source,
      target: e.target,
      ecolor: e.used ? "#3A3A40" : "#26262C",
      width: e.is_direct ? 2.2 : 1.2,
    },
    classes: e.used ? "" : "unused",
  }));
  return [...nodes, ...edges];
}

const STYLE: any[] = [
  {
    selector: "node",
    style: {
      "background-color": "data(color)",
      width: "data(size)",
      height: "data(size)",
      label: "data(label)",
      color: "#8A8A93",
      "font-family": "JetBrains Mono, monospace",
      "font-size": 8,
      "text-valign": "bottom",
      "text-margin-y": 3,
      "text-max-width": "90px",
      "border-width": 1.5,
      "border-color": "#000000",
      "border-opacity": 0.6,
      "transition-property": "opacity, border-color, border-width",
      "transition-duration": 150,
    },
  },
  {
    selector: 'node[kind="app"]',
    style: {
      shape: "round-rectangle",
      "font-size": 12,
      "font-weight": 700,
      color: "#F4F4F5",
      "text-valign": "center",
      "text-margin-y": 0,
      "border-width": 2,
      "border-color": APP_HEX,
    },
  },
  { selector: "node.suppressed", style: { "border-style": "dashed", "border-color": "#4A4A52", opacity: 0.55 } },
  {
    selector: "edge",
    style: {
      width: "data(width)",
      "line-color": "data(ecolor)",
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "target-arrow-color": "data(ecolor)",
      "arrow-scale": 0.6,
      opacity: 0.75,
    },
  },
  { selector: "edge.unused", style: { "line-style": "dashed", opacity: 0.35 } },
  { selector: ".faded", style: { opacity: 0.1, "text-opacity": 0.1 } },
  { selector: "node.hl", style: { "border-width": 3, "border-color": APP_HEX } },
  { selector: "edge.hl", style: { "line-color": APP_HEX, "target-arrow-color": APP_HEX, width: 2.6, opacity: 1 } },
];

export default function DependencyGraph({
  graph,
  onSelect,
}: {
  graph: AppGraph;
  onSelect: (node: GraphNode | null) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: toElements(graph),
      style: STYLE,
      layout: {
        name: "fcose",
        quality: "default",
        animate: true,
        animationDuration: 600,
        nodeSeparation: 80,
        idealEdgeLength: 60,
        nodeRepulsion: 6000,
      } as any,
      minZoom: 0.2,
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      const trail = node.predecessors().union(node);
      cy.elements().removeClass("hl faded");
      cy.elements().not(trail).addClass("faded");
      trail.addClass("hl");
      onSelect(node.data("raw"));
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass("hl faded");
        onSelect(null);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect]);

  return <div ref={ref} className="h-full w-full" />;
}
