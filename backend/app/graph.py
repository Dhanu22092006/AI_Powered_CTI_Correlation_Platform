from .db import neo_driver

def add_indicator_graph(indicator: dict, source: str, related: list[dict]):
    if neo_driver is None:
        return
    key = f"{indicator['type']}:{indicator['value'].lower()}"
    with neo_driver.session() as session:
        session.run(
            "MERGE (n:Entity {key:$key}) SET n.type=$type, n.value=$value "
            "MERGE (s:Source {name:$source}) MERGE (n)-[:OBSERVED_IN {evidence:'source record'}]->(s)",
            key=key, type=indicator["type"], value=indicator["value"], source=source
        )
        for other in related:
            other_key = f"{other['type']}:{other['value'].lower()}"
            session.run(
                "MERGE (a:Entity {key:$a}) SET a.type=$atype, a.value=$avalue "
                "MERGE (b:Entity {key:$b}) SET b.type=$btype, b.value=$bvalue "
                "MERGE (a)-[r:CO_MENTIONED_IN {source:$source}]->(b) "
                "SET r.confidence='low', r.evidence='Both indicators appeared in the same submitted record; relationship is inferred'",
                a=key, atype=indicator["type"], avalue=indicator["value"],
                b=other_key, btype=other["type"], bvalue=other["value"], source=source
            )

def get_graph(limit: int = 150):
    if neo_driver is None:
        return {"nodes": [], "edges": []}
    with neo_driver.session() as session:
        rows = session.run(
            "MATCH (a:Entity)-[r:CO_MENTIONED_IN]->(b:Entity) "
            "RETURN a.key AS source,a.type AS st,a.value AS sv, type(r) AS rel, "
            "b.key AS target,b.type AS tt,b.value AS tv LIMIT $limit",
            limit=limit
        )
        nodes, edges, seen = [], [], set()
        for row in rows:
            for key, typ, val in [(row["source"], row["st"], row["sv"]), (row["target"], row["tt"], row["tv"])]:
                if key and key not in seen:
                    seen.add(key)
                    nodes.append({"id": key, "type": typ or "indicator", "label": val or key})
            edges.append({"source": row["source"], "target": row["target"], "label": row["rel"]})
        return {"nodes": nodes, "edges": edges}
