// Unity id - averma3
// Name - Akash Verma
// Student id - 200077895

import java.util.*;


public class GraphSearch{


	static class node{
		private String city = new String();
		private boolean visited;
		private ArrayList<node> neighbours;
		private ArrayList<String> path;

		public node(String city){
			this.city = city;
			this.visited = false;
			this.neighbours = new ArrayList<node>();
			this.path = new ArrayList<String>();
		}

		public void setVisited(boolean visited){
			this.visited = visited;
		}

		public void addNeighbour(node neighbour){
			this.neighbours.add(neighbour);
		}

		public void addToPath(String city){
			this.path.add(city);
		}

		public void addToPath(ArrayList<String> pathToAdd){
			this.path.addAll(pathToAdd);
		}

		public boolean getVisited(){
			return this.visited;
		}

		public ArrayList<String> getPath(){
			return this.path;
		}

		public ArrayList<node> getNeighbours(){
			Collections.sort(this.neighbours.subList(0, this.neighbours.size()), new Comparator<node>(){
				public int compare(node node1, node node2) {
			    if (node1.city == node2.city) {
			        return 0;
			    }
			    if (node1.city == null) {
			        return -1;
			    }
			    if (node2.city == null) {
			        return 1;
			    }
			    return node1.city.compareTo(node2.city);
			  }
			});
			return this.neighbours;
		} 

		public ArrayList<node> getNeighboursDecreasing(){
			Collections.sort(this.neighbours.subList(0, this.neighbours.size()), new Comparator<node>(){
				public int compare(node node1, node node2) {
			    if (node1.city == node2.city) {
			        return 0;
			    }
			    if (node1.city == null) {
			        return -1;
			    }
			    if (node2.city == null) {
			        return 1;
			    }
			    return node1.city.compareTo(node2.city);
			  }
			});
			Collections.reverse(this.neighbours);
			return this.neighbours;
		} 

	}

	public ArrayList<String> bfs(node root, String dest){
		ArrayList<String> visited = new ArrayList<String>();
		root.addToPath(root.city);
		if(root.city.equals(dest)){
			return root.getPath();
		}
		root.setVisited(true);
		Queue<node> queue = new LinkedList<node>();
		queue.add(root);
		while(!queue.isEmpty()){
			node curr = queue.remove();
			visited.add(curr.city);
			if(curr.city.equals(dest)){
				System.out.println(" Number of nodes visited before path found by bfs: " + visited.size());
				return curr.getPath();
			}

			for(node neighbour : curr.getNeighbours()){
				if(neighbour.getVisited() == false){
					queue.add(neighbour);
					neighbour.setVisited(true);
					neighbour.addToPath(curr.getPath());
					neighbour.addToPath(neighbour.city);
				}
			}

		}
		return (new ArrayList<String>());

	}

	public ArrayList<String> dfs(node root, String dest){
		ArrayList<String> visited = new ArrayList<String>();
		root.addToPath(root.city);
		if(root.city.equals(dest)){
			return root.getPath();
		}

		root.setVisited(true);
		Stack<node> stack = new Stack<node>();	
		stack.push(root);
		while(!stack.empty()){
			node curr = stack.pop();
			visited.add(curr.city);
			if(curr.city.equals(dest)){
				System.out.println(" Number of nodes visited before path found by dfs: " + visited.size());
				return curr.getPath();
			}

			for(node neighbour : curr.getNeighboursDecreasing()){
				if(neighbour.getVisited() == false){
					stack.push(neighbour);
					neighbour.setVisited(true);
					neighbour.addToPath(curr.getPath());
					neighbour.addToPath(neighbour.city);
				}
			}

		}
		return (new ArrayList<String>());

	}

	public static void main(String[] args){

		GraphSearch gs = new GraphSearch();

		String searchType = args[0];
		String src = args[1];
		String dest = args[2];
		String s ="arad,bucharest,craiova,dobreta,eforie,fagaras,giurgiu,hirsova,iasi,lugoj,mehadia,neamt,oradea,pitesti,rimnicu_vilcea,sibiu,timisoara,urziceni,vaslui,zerind";
		String[] citynames = s.split(",");
		ArrayList<String> cities = new ArrayList<String>();
		ArrayList<node> graph = new ArrayList<node>();
		ArrayList<String> path = new ArrayList<String>();

		for(int i = 0; i < citynames.length ; i++){
			cities.add(citynames[i]);
			node node = new node(citynames[i]);
			graph.add(node);
		}

		String r = "oradea,zerind,71;arad,timisoara,118;lugoj,mehadia,70;oradea,sibiu,151;dobreta,craiova,120;sibiu,fagaras,99;pitesti,craiova,138;bucharest,pitesti,101;bucharest,giurgiu,90;vaslui,urziceni,142;hirsova,eforie,86;neamt,iasi,87;zerind,arad,75;timisoara,lugoj,111;dobreta,mehadia,75;arad,sibiu,140;sibiu,rimnicu_vilcea,80;rimnicu_vilcea,craiova,146;rimnicu_vilcea,pitesti,97;bucharest,fagaras,211;bucharest,urziceni,85;hirsova,urziceni,98;vaslui,iasi,92";

		String[] roads = r.split(";");
		
		for(int i = 0; i < roads.length; i++){
			String[] split = roads[i].split(",");
			int srcIndex = cities.indexOf(split[0]);
			int destIndex = cities.indexOf(split[1]);
			graph.get(srcIndex).addNeighbour(graph.get(destIndex));
			graph.get(destIndex).addNeighbour(graph.get(srcIndex));
		}

		int srcId = cities.indexOf(src);

		if(searchType.equals("bfs")){
			path = gs.bfs(graph.get(srcId), dest);
		} else if(searchType.equals("dfs")){
			path = gs.dfs(graph.get(srcId), dest);
		}
		else{
			System.out.println(" Invalid search type!!");
		}

		if(path.size() > 0){
			System.out.println(" -- The length of path from " + src + " to " + dest + " is " + (path.size()-1) + " using " + searchType);
			for(String city: path){
				System.out.print(city + "    ");
			}
		} else{
			System.out.println(" -- Either src and dest are same or No path from " + src + " to " + dest);
		}

		System.out.println();

	}


}