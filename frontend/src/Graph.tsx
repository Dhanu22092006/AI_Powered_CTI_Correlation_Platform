import {useEffect, useRef} from 'react'
import cytoscape from 'cytoscape'
export default function Graph({graph}:{graph:any}){
 const ref=useRef<HTMLDivElement>(null)
 useEffect(()=>{
  if(!ref.current)return
  const cy=cytoscape({container:ref.current,elements:[
   ...(graph.nodes||[]).map((n:any)=>({data:{id:n.id,label:n.label,type:n.type}})),
   ...(graph.edges||[]).map((e:any,i:number)=>({data:{id:`e${i}`,source:e.source,target:e.target,label:e.label}}))
  ],style:[
   {selector:'node',style:{'background-color':'#2d8cff','label':'data(label)','color':'#e8eef8','font-size':10,'text-wrap':'wrap','text-max-width':100,'text-valign':'bottom','text-margin-y':7,'width':28,'height':28,'border-width':1,'border-color':'#79b8ff'}},
   {selector:'edge',style:{'width':1.5,'line-color':'#53677f','target-arrow-color':'#53677f','target-arrow-shape':'triangle','curve-style':'bezier','label':'data(label)','font-size':8,'color':'#9fb0c5','text-background-opacity':0}},
   {selector:':selected',style:{'background-color':'#f5a623','line-color':'#f5a623'}}
  ],layout:{name:'cose',animate:false},background:'transparent'})
  return ()=>cy.destroy()
 },[graph])
 return <div ref={ref} className="cy-graph"/>
}
