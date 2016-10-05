// Unity id - averma3
// Name - Akash Verma
// Student id - 200077895

import java.util.*;
import java.lang.Math.*;
import java.io.*;


public class SearchUSA{


	static class node{
		String city = new String();
		private boolean visited;
		private double lat;
		private double lng;
		private double heuristic;
		private double f;
		private double pathlen;
		private ArrayList<edge> neighbours;
		ArrayList<String> path;

		public node(String city){
			this.city = city;
			this.visited = false;
			this.neighbours = new ArrayList<edge>();
			this.path = new ArrayList<String>();
			this.lat = 0.0;
			this.lng = 0.0;
			this.heuristic = 0.0;
			this.f = 0.0;
			this.pathlen = 0.0;
		}

		public node(String city, double lat, double lng){
			this.city = city;
			this.visited = false;
			this.neighbours = new ArrayList<edge>();
			this.path = new ArrayList<String>();
			this.lat = lat;
			this.lng = lng;
			this.heuristic = 0.0;
			this.pathlen = 0.0;
		}

		public void setVisited(boolean visited){
			this.visited = visited;
		}

		public void setLat(double lat){
			this.lat = lat;
		}

		public void setLng(double lng){
			this.lng = lng;
		}

		public void setHeuristic(double heuristic){
			this.heuristic = heuristic;
		}

		public void setf(double f){
			this.f = f;
		}

		public void setPathlen(double pathlen){
			this.pathlen = pathlen;
		}

		public void addNeighbour(edge neighbour){
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

		public double getLat(){
			return this.lat;
		}

		public double getLng(){
			return this.lng;
		}

		public double getHeuristic(){
			return this.heuristic;
		}

		public double getf(){
			return this.f;
		}

		public double getPathlen(){
			return this.pathlen;
		}

		public ArrayList<edge> getNeighbours(){
			return this.neighbours;
		} 

	}

	static class edge{
		node neighbour;
		double len;
		public edge(node neighbour, double len){
			this.neighbour = neighbour;
			this.len = len;
		}
	}


	public double heuristic(node city1, node city2){
		double dx = city1.getLat() - city2.getLat();
		double dy = city1.getLng() - city2.getLng();
		return Math.sqrt(Math.pow((69.5 * dx),2) + Math.pow((69.5 * Math.cos((city1.getLat() + city2.getLat())/360 * Math.PI) * (dy)), 2));
	}

	public ArrayList<String> greedy(node root, node dest){
		
		Queue<node> open = new PriorityQueue<node>(11, new Comparator<node>(){
			public int compare(node node1, node node2) {
				Double val1 = Double.valueOf(node1.getHeuristic());
				Double val2 = Double.valueOf(node2.getHeuristic());
			    return val1.compareTo(val2);
			}
		});

		ArrayList<node> path = new ArrayList<node>();
		ArrayList<node> visited = new ArrayList<node>();
		root.setVisited(true);
		root.addToPath(root.city);
		root.setPathlen(0.0);
		open.add(root);
		while(!open.isEmpty()){
			node curr = open.poll();
			
			if (curr.city.equalsIgnoreCase(dest.city)){
				System.out.println("Total number of nodes visited = " + visited.size());
				System.out.print("Nodes visited : " );
				for (int i = 0; i< visited.size(); i++ ) {
					System.out.print(visited.get(i).city + ", ");
				}
				System.out.println();
				System.out.println("Total number of nodes in path = " + curr.getPath().size());
				System.out.println("Total distance of path = " + curr.getPathlen());
				return curr.getPath();
			}
			visited.add(curr);
			for(edge edge : curr.getNeighbours()){
				if(!visited.contains(edge.neighbour)){
					edge.neighbour.setHeuristic(heuristic(edge.neighbour, dest));
					open.add(edge.neighbour);
					edge.neighbour.path = new ArrayList<String>();
					edge.neighbour.addToPath(curr.getPath());
					edge.neighbour.addToPath(edge.neighbour.city);
					edge.neighbour.setPathlen(curr.getPathlen() + edge.len);
				}
			}
		}
		return new ArrayList<String>();
	}


	public ArrayList<String> astar(node root, node dest){
		
		Queue<node> open = new PriorityQueue<node>(11, new Comparator<node>(){
			public int compare(node node1, node node2) {
				Double val1 = Double.valueOf(node1.getf());
				Double val2 = Double.valueOf(node2.getf());
			    return val1.compareTo(val2);
			}
		});

		ArrayList<node> path = new ArrayList<node>();
		ArrayList<node> visited = new ArrayList<node>();
		root.setVisited(true);
		root.addToPath(root.city);
		root.setPathlen(0.0);
		open.add(root);
		while(!open.isEmpty()){
			node curr = open.poll();
			
			if (curr.city.equalsIgnoreCase(dest.city)){
				System.out.println("Total number of nodes visited = " + visited.size());
				System.out.print("Nodes visited : " );
				for (int i = 0; i< visited.size(); i++ ) {
					System.out.print(visited.get(i).city + ", ");
				}
				System.out.println();
				System.out.println("Total number of nodes in path = " + curr.getPath().size());
				System.out.println("Total distance of path = " + curr.getPathlen());
				return curr.getPath();
			}
			if(!visited.contains(curr)){
				visited.add(curr);
			}
			for(edge edge : curr.getNeighbours()){
				double new_len = curr.getPathlen() + edge.len;
				if(edge.neighbour.getPathlen() == 0.0 || new_len < edge.neighbour.getPathlen()){
					double heuristic = heuristic(edge.neighbour, dest);
					edge.neighbour.setHeuristic(heuristic);
					edge.neighbour.path = new ArrayList<String>();
					edge.neighbour.addToPath(curr.getPath());
					edge.neighbour.addToPath(edge.neighbour.city);
					edge.neighbour.setPathlen(new_len);
					edge.neighbour.setf(new_len + heuristic);
					open.add(edge.neighbour);
				}
			}
		}
		return new ArrayList<String>();
	}	


	public ArrayList<String> uniform(node root, node dest){
		
		Queue<node> open = new PriorityQueue<node>(11, new Comparator<node>(){
			public int compare(node node1, node node2) {
				Double val1 = Double.valueOf(node1.getPathlen());
				Double val2 = Double.valueOf(node2.getPathlen());
			    return val1.compareTo(val2);
			}
		});

		ArrayList<node> path = new ArrayList<node>();
		ArrayList<node> visited = new ArrayList<node>();
		root.setVisited(true);
		root.addToPath(root.city);
		root.setPathlen(0.0);
		open.add(root);
		while(!open.isEmpty()){
			node curr = open.poll();
			
			if (curr.city.equalsIgnoreCase(dest.city)){
				System.out.println("Total number of nodes visited = " + visited.size());
				System.out.print("Nodes visited : " );
				for (int i = 0; i< visited.size(); i++ ) {
					System.out.print(visited.get(i).city + ", ");
				}
				System.out.println();
				System.out.println("Total number of nodes in path = " + curr.getPath().size());
				System.out.println("Total distance of path = " + curr.getPathlen());
				return curr.getPath();
			}
			if(!visited.contains(curr)){
				visited.add(curr);
			}
			for(edge edge : curr.getNeighbours()){
				double new_len = curr.getPathlen() + edge.len;
				
				if(!visited.contains(edge.neighbour) && !open.contains(edge.neighbour)){
					edge.neighbour.setPathlen(new_len);
					edge.neighbour.path = new ArrayList<String>();
					edge.neighbour.addToPath(curr.getPath());
					edge.neighbour.addToPath(edge.neighbour.city);
					open.add(edge.neighbour);
				}
				else if(open.contains(edge.neighbour) && new_len < edge.neighbour.getPathlen()){
					edge.neighbour.setPathlen(new_len);
					edge.neighbour.path = new ArrayList<String>();
					edge.neighbour.addToPath(curr.getPath());
					edge.neighbour.addToPath(edge.neighbour.city);
				}
			}
		}
		return new ArrayList<String>();
	}

	public static void main(String[] args){

		SearchUSA su = new SearchUSA();

		String searchType = args[0];
		String src = args[1];
		String dest = args[2];
		String s ="";
		String[] citynames = s.split(",");
		ArrayList<String> cities = new ArrayList<String>();
		ArrayList<node> graph = new ArrayList<node>();
		ArrayList<String> path = new ArrayList<String>();

		try{
			File file = new File("uscity2.txt");
			FileReader fileReader = new FileReader(file);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			StringBuffer stringBuffer = new StringBuffer();
			String line;
			while ((line = bufferedReader.readLine()) != null) {
				String[] split = line.split(",");
				cities.add(split[0]);
				node node = new node(split[0], Double.parseDouble(split[1]), Double.parseDouble(split[2]));
				graph.add(node);
			}
			fileReader.close();
		}catch(Exception e){
			System.out.println("Exception");
		}
		
		try{
			File file2 = new File("usroads2.txt");
			FileReader fileReader2 = new FileReader(file2);
			BufferedReader bufferedReader2 = new BufferedReader(fileReader2);
			StringBuffer stringBuffer2 = new StringBuffer();
			String line2;
			while ((line2 = bufferedReader2.readLine()) != null) {
				String[] split = line2.split(",");
				int srcIndex = cities.indexOf(split[0]);
				int destIndex = cities.indexOf(split[1]);
				double len = Double.parseDouble(split[2]);
				edge e1 = new edge(graph.get(destIndex), len);
				edge e2 = new edge(graph.get(srcIndex), len);
				graph.get(srcIndex).addNeighbour(e1);
				graph.get(destIndex).addNeighbour(e2);
			}
			fileReader2.close();
		} catch(Exception e){
			System.out.println("Exception");
		}

		int srcId = cities.indexOf(src);
		int destId = cities.indexOf(dest);

		if(searchType.equalsIgnoreCase("greedy")){
			path = su.greedy(graph.get(srcId), graph.get(destId));
		} else if(searchType.equalsIgnoreCase("astar")){
			path = su.astar(graph.get(srcId),  graph.get(destId));
		}else if(searchType.equalsIgnoreCase("uniform")){
			path = su.uniform(graph.get(srcId),  graph.get(destId));
		}
		else{
			System.out.println(" Invalid search type!!");
		}

		if(path.size() > 0){
			for(String city: path){
				System.out.print(city + ", ");
			}
		} else{
			System.out.println(" -- Either src and dest are same or No path from " + src + " to " + dest);
		}

		System.out.println();

	}


}