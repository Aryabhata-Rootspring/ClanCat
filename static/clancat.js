MYEPSILON = 1e-8;
var id;
var scene;
var controls;
var camera;
var projector
var renderer = new THREE.WebGLRenderer();
var sica
var siai
var running = false
var exit = false


  /* Given 10,8 this returns the string "8:10" */
  function sortedVertexStr(i,j) {
     if (i<j) 
        return i.toString()+":"+j.toString();
    return j.toString()+":"+i.toString();
  };

  function addAndIncr(dic,key) {
     if (dic[key]==undefined) dic[key]=1;
     else dic[key]+=1;
  };    

  /* Used in conjunction with sortedVertexStr */
  function getIndividualVerts(s) {
     var nums = s.split(":");
     var ret =  {};
     ret.first = parseInt(nums[0]);
     ret.second = parseInt(nums[1]);
     return ret;
  };

  /* Used during getVertSequence */
  function findNextVert(idx,c,eArr) {
     var edgexipair ;
     var retval=undefined;
     if (idx >=0 && idx < eArr.length) {
          retval= eArr[idx];
          eArr[idx]=undefined;
          return retval;
          //Returns a string of the form "1:2"
     }
     else {
        for (var i=0; i < eArr.length; i++ ) {
           if (eArr[i]==undefined) continue;
           edgepair = getIndividualVerts(eArr[i]);
           if (c==edgepair.first || c==edgepair.second) {
               eArr[i]=undefined;
               if (c==edgepair.first) return edgepair.second;
               if (c==edgepair.second) return edgepair.first;
            //Returns a vertex index ie an integer
           }
        } 
     }
     return undefined;
  }
 
  /* Given all the edges induced by the triangulation of the 
     face, this basically gives the sequences of actual vertices `of the 
     polygon corresponding to the polyhedron face*/
  function getVertSequence(dic) {
     var retlist = new Array();
     var tmp = new Array();
     for (var k in dic) {
        if (dic[k]==1) tmp.push(k);
     }
     var pair = getIndividualVerts(findNextVert(0,null,tmp));
     retlist.push(pair.first);
     retlist.push(pair.second);
     var nextVert = findNextVert(-1,pair.second,tmp);
     while (retlist.indexOf(nextVert) == -1) {
         retlist.push(nextVert);
         nextVert = findNextVert(-1,nextVert,tmp);
     }
     return retlist;
  }

  /*Given a list of triangles (three vertices) corresponding to 
    a polyhedral face this function uses getVertSequence() to 
    compite the sequence of actual vertices of the polyhedral face*/ 
  function computeVertArray(lF,vertices) {
     var edges = {};
     var i;
     var edgeStr;
     for ( i = 0; i<lF.length;i++) {
        edgeStr =  sortedVertexStr(lF[i].a,lF[i].b);
        addAndIncr(edges,edgeStr);
        edgeStr =  sortedVertexStr(lF[i].b,lF[i].c);
        addAndIncr(edges,edgeStr);
        edgeStr =  sortedVertexStr(lF[i].c,lF[i].a);
        addAndIncr(edges,edgeStr);
     };
     var Arr = getVertSequence(edges);
     return Arr;
  }
  /* Given a list of triangles corresponding to the triangulation of
     a polyhedral face, compute the midpoint*/
  function computeMidpoints(listOfFaces, faceArray, vertArray) {
     console.log(listOfFaces);
     console.log(vertArray);
     var s= new Set();
     var i;
     for ( i = 0; i<listOfFaces.length;i++) {
        s.add(faceArray[listOfFaces[i]].a);
        s.add(faceArray[listOfFaces[i]].b);
        s.add(faceArray[listOfFaces[i]].c);
     }
     var Arr = Array.from(s);
     var midp = new THREE.Vector3();
     for (i = 0; i< Arr.length;i++){
         midp.x += vertArray[Arr[i]].x;
         midp.y += vertArray[Arr[i]].y;
         midp.z += vertArray[Arr[i]].z;
     }
     midp.x /= Arr.length;
     midp.y /= Arr.length;
     midp.z /= Arr.length;

     return midp;
   };

  function getPointAbovePlanePoint(planePoint,plane,dist) {
    var ret =planePoint.clone();
    var planeNormal = plane.normal.normalize();
    ret.addScaledVector(planeNormal,dist);
    return ret;
  };

  function getPointInPlane(planePoint,planeDir,dist) {
    var ret = planePoint.clone();
    ret.addScaledVector(planeDir.normalize(),dist);
    return ret;
  };

  function getAxisNormalDirectionAlongFace(faceVertArr,axisStr) {
    var axisDir,idx;
    var edgeDir = new THREE.Vector3();
    if (axisStr == 'X' || axisStr == 'x') axisDir = new THREE.Vector3(1,0,0);
    if (axisStr == 'Y' || axisStr == 'y') axisDir = new THREE.Vector3(0,1,0);
    if (axisStr == 'Z' || axisStr == 'z') axisDir = new THREE.Vector3(0,0,1);
    if (axisDir == undefined) return undefined;
    for (var i=0; i< faceVertArr.length;i++) {
       if (i+1==faceVertArr.length) idx=0;
       else idx=i+1;
       edgeDir.x = faceVertArr[idx].x-faceVertArr[i].x; 
       edgeDir.y = faceVertArr[idx].y-faceVertArr[i].y; 
       edgeDir.z = faceVertArr[idx].z-faceVertArr[i].z; 
       if (axisDir.dot(edgeDir)==0) return edgeDir;
    }
    return null;
  };
  
// line intercept math by Paul Bourke http://paulbourke.net/geometry/pointlineplane/
// Determine the intersection point of two line segments
// Return FALSE if the lines don't intersect
function intersectLinesXY(x1, y1, x2, y2, x3, y3, x4, y4) {

  // Check if none of the lines are of length 0
	if ((x1 === x2 && y1 === y2) || (x3 === x4 && y3 === y4)) {
		return false
	}

	denominator = ((y4 - y3) * (x2 - x1) - (x4 - x3) * (y2 - y1))

  // Lines are parallel
	if (denominator === 0) {
		return false
	}

	let ua = ((x4 - x3) * (y1 - y3) - (y4 - y3) * (x1 - x3)) / denominator
	let ub = ((x2 - x1) * (y1 - y3) - (y2 - y1) * (x1 - x3)) / denominator

  // is the intersection along the segments
	if (ua < 0 || ua > 1 || ub < 0 || ub > 1) {
		return false
	}

  // Return a object with the x and y coordinates of the intersection
	let x = x1 + ua * (x2 - x1)
	let y = y1 + ua * (y2 - y1)

	return {x, y}
}


/*
   Calculate the line segment PaPb that is the shortest route between
   two lines P1P2 and P3P4. Calculate also the values of mua and mub where
      Pa = P1 + mua (P2 - P1)
      Pb = P3 + mub (P4 - P3)
   Return FALSE if no solution exists.
*/
function LineLineIntersect(
   p1,p2,p3,p4)
{
   var p13,p43,p21;
   var d1343,d4321,d1321,d4343,d2121;
   var numer,denom;
   var mua,mub;
   var pa,pb;

   p13 = new THREE.Vector3();
   p43 = new THREE.Vector3();
   p21= new THREE.Vector3();
   pa= new THREE.Vector3();
   pb= new THREE.Vector3();


   p13.x = p1.x - p3.x;
   p13.y = p1.y - p3.y;
   p13.z = p1.z - p3.z;
   p43.x = p4.x - p3.x;
   p43.y = p4.y - p3.y;
   p43.z = p4.z - p3.z;

   if (Math.abs(p43.x) < MYEPSILON && Math.abs(p43.y) < MYEPSILON && Math.abs(p43.z) < MYEPSILON)
      return(undefined);

   p21.x = p2.x - p1.x;
   p21.y = p2.y - p1.y;
   p21.z = p2.z - p1.z;
   if (Math.abs(p21.x) < MYEPSILON && Math.abs(p21.y) < MYEPSILON && Math.abs(p21.z) < MYEPSILON)
      return(undefined);

   d1343 = p13.x * p43.x + p13.y * p43.y + p13.z * p43.z;
   d4321 = p43.x * p21.x + p43.y * p21.y + p43.z * p21.z;
   d1321 = p13.x * p21.x + p13.y * p21.y + p13.z * p21.z;
   d4343 = p43.x * p43.x + p43.y * p43.y + p43.z * p43.z;
   d2121 = p21.x * p21.x + p21.y * p21.y + p21.z * p21.z;

   denom = d2121 * d4343 - d4321 * d4321;
   if (Math.abs(denom) < MYEPSILON)
      return(undefined);
   numer = d1343 * d4321 - d1321 * d4343;

   if (denom) mua = numer / denom;
   else {
      if (numer==0) mua = 0;
      else return undefined;
   }
   
   mub = (d1343 + d4321 * (mua)) / d4343;


   pa = new THREE.Vector3();
   pb = new THREE.Vector3();

   pa.x = p1.x + mua * p21.x;
   pa.y = p1.y + mua * p21.y;
   pa.z = p1.z + mua * p21.z;
   pb.x = p3.x + mub * p43.x;
   pb.y = p3.y + mub * p43.y;
   pb.z = p3.z + mub * p43.z;

   return {"p1":pa,"p2":pb,"dist":pa.distanceTo(pb)};
}



class Box {

    constructor(attr) {
       this.geom = new THREE.BoxGeometry(attr.L,attr.H,attr.D);
       if (attr.color != undefined) 
          this.material = new THREE.MeshBasicMaterial({color:attr.color});
       else
          this.material = new THREE.MeshBasicMaterial({color:0xff00});
      this.solid= new THREE.Mesh(this.geom, this.material);
      this.ledges = new THREE.EdgesGeometry( this.geom);
      this.lline = new THREE.LineSegments( this.ledges, new THREE.LineBasicMaterial( { color: 0x0f0f0f } ) );
      this.obj = new THREE.Group();
      this.obj.add(this.solid);
      this.obj.add(this.lline);

       this.HD0 = new Array();
       this.HD1 = new Array();
       this.LD0 = new Array();
       this.LD1 = new Array();
       this.LH0 = new Array();
       this.LH1 = new Array();

       this.markFaces(this.geom);
       this.mass = attr.mass;
    };


   markFaces(geom) {
      var i;
      for (i=0; i<geom.faces.length;i++) {
        if (geom.faces[i].normal.equals(new THREE.Vector3(1,0,0),MYEPSILON)) {
             this.HD0.push(i);
        }
        if (geom.faces[i].normal.equals(new THREE.Vector3(-1,0,0),MYEPSILON)) {
             this.HD1.push(i);
        }
        if (geom.faces[i].normal.equals(new THREE.Vector3(0,1,0),MYEPSILON)) {
             this.LD0.push(i);
        }
	if (geom.faces[i].normal.equals(new THREE.Vector3(0,-1,0),MYEPSILON)) {
             this.LD1.push(i);
	}
        if (geom.faces[i].normal.equals(new THREE.Vector3(0,0,1),MYEPSILON)) {
             this.LH0.push(i);
        }
        if (geom.faces[i].normal.equals(new THREE.Vector3(0,0,-1),MYEPSILON)) {
             this.LH1.push(i);
        }

      } 
   }

  addToScene(scene) {
    scene.add(this.obj); 
  }


  getNormal(s) {
     if (s=="LD0") return this.LD0[0].normal;
     if (s=="LD1") return this.LD1[0].normal;
     if (s=="LH0") return this.LH0[0].normal;
     if (s=="LH1") return this.LH1[0].normal;
     if (s=="HD0") return this.HD0[0].normal;
     if (s=="HD1") return this.HD0[0].normal;
  }

  getPlane_ex(faceidx) {
    var newverts = this.getCurrentVertexPositions();
    return new THREE.Plane().setFromCoplanarPoints(                           
                           newverts[this.geom.faces[faceidx].a],
                           newverts[this.geom.faces[faceidx].b],
                           newverts[this.geom.faces[faceidx].c]
                           );
  };
  getPlane(s) {
     if (s=="LD0") return this.getPlane_ex(this.LD0[0]);
     if (s=="LD1") return this.getPlane_ex(this.LD1[0]);
     if (s=="LH0") return this.getPlane_ex(this.LH0[0]);
     if (s=="LH1") return this.getPlane_ex(this.LH1[0]);
     if (s=="HD0") return this.getPlane_ex(this.HD0[0]);
     if (s=="HD1") return this.getPlane_ex(this.HD1[0]);
  };

  getFaceVertPoints(indices) {
     var ret = new Array();
     for (var i = 0; i< indices.length;i++) ret.push(this.geom.vertices[i].clone());
     return ret;
  };

  getFaceVerts(s) {
     if (s=="LD0") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LD0),this.geom.vertices));
     if (s=="LD1") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LD1),this.geom.vertices));
     if (s=="LH0") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LH0),this.geom.vertices));
     if (s=="LH1") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LH1),this.geom.vertices));
     if (s=="HD0") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.HD0),this.geom.vertices));
     if (s=="HD1") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.HD1),this.geom.vertices));
  };

  getFaceMidp(s) {
     if (s=="LD0") return this.computeMidPt(this.LD0);
     if (s=="LD1") return this.computeMidPt(this.LD1);
     if (s=="LH0") return this.computeMidPt(this.LH0);
     if (s=="LH1") return this.computeMidPt(this.LH1);
     if (s=="HD0") return this.computeMidPt(this.HD0);
     if (s=="HD1") return this.computeMidPt(this.HD1);
  };

  computeMidPt(listOfFaces) {
     return computeMidpoints(listOfFaces,this.geom.faces,this.geom.vertices);
  };

  //From https://stackoverflow.com/a/38306162/932184`
  getPosition() {
    this.geom.computeBoundingBox();
    var center = new THREE.Vector3();
    center = this.geom.boundingBox.getCenter(center);
    var retval = this.obj.localToWorld(center);
    return retval;
  };
  setPos(x,y,z) {
    this.obj.position.set(x,y,z);
    this.obj.updateMatrixWorld();
   };

  //Probably should be common to all solid objects
  rotateX(rad) {
    this.obj.rotation.x = rad;
    this.obj.updateMatrixWorld();
  };
  rotateY(rad) {
    this.obj.rotation.y = rad;
    this.obj.updateMatrixWorld();
  };
  rotateZ(rad) {
    this.obj.rotation.z = rad;
    this.obj.updateMatrixWorld();
  };

 getCurrentVertexPositions() {
    var newverts = new Array();
    for (var i =0; i< this.geom.vertices.length;i++) {
          newverts.push(this.solid.localToWorld(this.solid.geometry.vertices[i].clone()));
   }
   return newverts;
 }

}

function makeDot (p,scene) {
  var dotGeometry = new THREE.Geometry();
  dotGeometry.vertices.push(new THREE.Vector3( p.x,p.y,p.z));
  var dotMaterial = new THREE.PointsMaterial( { size: 10, sizeAttenuation: false } );
  var dot = new THREE.Points( dotGeometry, dotMaterial );
  scene.add( dot );
};


//RESUME https://stackoverflow.com/a/29319809/932184
class InclinedPlane {

    constructor(attr,scene) {
       /*
           L
           D
           A1
           A2 Optional

       */


       var pt1 = new THREE.Vector3(-attr.L/2,0,0);
       var pt2 = new THREE.Vector3(attr.L/2,0,0);
       var a1 = attr.A1;
       var a2 = attr.A2;

       if (a2==undefined) a2 = Math.PI/2;
       var pt3_2 = this.calculateThirdVert(pt1,pt2,a1,a2);
       var pt3 = new THREE.Vector3(pt3_2.x,pt3_2.y,0);



       var pt1d = new THREE.Vector3(pt1.x,pt1.y,pt1.z-attr.D);
       var pt2d = new THREE.Vector3(pt2.x,pt2.y,pt2.z-attr.D);
       var pt3d = new THREE.Vector3(pt3.x,pt3.y,pt3.z-attr.D);


/*
       makeDot(pt1,scene);
       makeDot(pt2,scene);
       makeDot(pt3,scene);
       makeDot(pt1d,scene);
       makeDot(pt2d,scene);
       makeDot(pt3d,scene);
 */      
       //Setting up the five faces
       this.HD0 = new Array();
       this.HD1 = new Array();
       this.LD1 = new Array();
       this.LH0 = new Array();
       this.LH1 = new Array();

       this.geom = new THREE.Geometry();
       this.geom.vertices.push(pt1,pt2,pt3,pt1d,pt2d,pt3d);
        // vertices
/*
       this.geom.vertices = [
    
    
        new THREE.Vector3( -10,  0, 0 ), // A       (0)
        new THREE.Vector3(  10,  0, 0 ), // B       (1)
        new THREE.Vector3(  5,  5,  0 ), // C       (2)
        new THREE.Vector3( -10,  0,  -10 ), // D       (3)
        new THREE.Vector3( 10, 0, -10 ), // E       (4)
        new THREE.Vector3(  5, 5, -10 ), // F       (5)
        
    ];
*/

    // faces - in counterclockwise winding order
     this.geom.faces.push(
      new THREE.Face3(1,2,0),new THREE.Face3(3,5,4),
      new THREE.Face3(5,2,1),new THREE.Face3(5,1,4),
      new THREE.Face3(3,0,2),new THREE.Face3(2,5,3),
      new THREE.Face3(0,3,4),new THREE.Face3(4,1,0));
    
    
       // normals ( since they are not specified directly )
       this.geom.computeFaceNormals();
       this.geom.computeVertexNormals();
       this.solid =  new THREE.Mesh( this.geom, new THREE.MeshNormalMaterial({transparent:false, opacity:1, color: "#0c64f2"}) );

       this.ledges = new THREE.EdgesGeometry( this.geom);
       this.lline = new THREE.LineSegments( this.ledges, new THREE.LineBasicMaterial( { color: 0xffffff } ) );

       this.obj = new THREE.Group();
       this.obj.add(this.solid);
       this.obj.add(this.lline);

       this.LH0.push(0);
       this.LH1.push(1);
       this.HD0.push(2,3);
       this.HD1.push(4,5);
       this.LD1.push(6,7);


    }

   calculateThirdVert(pt1,pt2,alp1,alp2) {
      
      var sidedir = new THREE.Vector3(pt2.x-pt1.x,pt2.y-pt1.y,pt2.z-pt1.z);
      var incdir = sidedir.clone();
      var otherdir = sidedir.clone();

      incdir = incdir.applyAxisAngle(new THREE.Vector3(0,0,1),alp1);
      otherdir = otherdir.applyAxisAngle(new THREE.Vector3(0,0,1),Math.PI-alp2);

      var pt1a = pt1.clone();
      var pt2a = pt2.clone();
      pt1a = pt1a.addScaledVector(incdir,10);
      pt2a = pt2a.addScaledVector(otherdir,10);
      
      var res = LineLineIntersect(pt1,pt1a,pt2,pt2a);
      if (res!=undefined && res.dist < MYEPSILON) return res.p1;
      return undefined;

    };

  getNormal(s) {
     if (s=="LD1") return this.LD1[0].normal;
     if (s=="LH0") return this.LH0[0].normal;
     if (s=="LH1") return this.LH1[0].normal;
     if (s=="HD0") return this.HD0[0].normal;
     if (s=="HD1") return this.HD1[0].normal;
  }


  getPlane_ex(faceidx) {
    var newverts = this.getCurrentVertexPositions();
    return new THREE.Plane().setFromCoplanarPoints(                           
                           newverts[this.geom.faces[faceidx].a],
                           newverts[this.geom.faces[faceidx].b],
                           newverts[this.geom.faces[faceidx].c]
                           );
  };
  getPlane(s) {
     if (s=="LD1") return this.getPlane_ex(this.LD1[0]);
     if (s=="LH0") return this.getPlane_ex(this.LH0[0]);
     if (s=="LH1") return this.getPlane_ex(this.LH1[0]);
     if (s=="HD0") return this.getPlane_ex(this.HD0[0]);
     if (s=="HD1") return this.getPlane_ex(this.HD1[0]);
  };

  getFaceVertPoints(indices) {
     var ret = new Array();
     for (var i = 0; i< indices.length;i++) ret.push(this.geom.vertices[i]);
     return ret;
  };

  getFaceList(lf) {
    var arrFaces = new Array();
    for (var i=0; i <lf.length;i++) arrFaces.push(this.geom.faces[lf[i]]);
    return arrFaces;
  };

  getFaceVerts(s) {
     if (s=="LD1") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LD1),this.geom.vertices));
     if (s=="LH0") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LH0),this.geom.vertices));
     if (s=="LH1") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.LH1),this.geom.vertices));
     if (s=="HD0") return this.getFaceVertPoints(computeVertArray(this.getFaceList(this.HD0),this.geom.vertices));
     if (s=="HD1") return this.getFaceVertPoints(computeVertArray(thsi.getFaceList(this.HD1),this.geom.vertices));
  };

  getFaceMidp(s) {
     if (s=="LD1") return this.computeMidPt(this.LD1);
     if (s=="LH0") return this.computeMidPt(this.LH0);
     if (s=="LH1") return this.computeMidPt(this.LH1);
     if (s=="HD0") return this.computeMidPt(this.HD0);
     if (s=="HD1") return this.computeMidPt(this.HD1);
  };


  computeMidPt(listOfFaces) {
     return computeMidpoints(listOfFaces,this.geom.faces,this.geom.vertices);
  };

  addToScene(scene) {
    scene.add(this.obj); 
  }

  //From https://stackoverflow.com/a/38306162/932184`
  getPosition() {
    this.geom.computeBoundingBox();
    var center = new THREE.Vector3();
    center = this.geom.boundingBox.getCenter(center);
    var retval = this.obj.localToWorld(center);
    return retval;
  }
  setPos(x,y,z) {
    this.obj.position.set(x,y,z);
    this.obj.updateMatrixWorld();
   }
  //Probably should be common to all solid objects
  rotateX(rad) {
    this.obj.rotation.x = rad;
    this.obj.updateMatrixWorld();
  };
  rotateY(rad) {
    this.obj.rotation.y = rad;
    this.obj.updateMatrixWorld();
  };
  rotateZ(rad) {
    this.obj.rotation.z += rad;
    this.obj.updateMatrixWorld();
  };
 getCurrentVertexPositions() {
    var newverts = new Array();
    for (var i =0; i< this.geom.vertices.length;i++) {
          newverts.push(this.solid.localToWorld(this.solid.geometry.vertices[i].clone()));
   }
   return newverts;
 }

}

 class Pulley {
    constructor(attr) {
/*
       const geometry = new THREE.CircleBufferGeometry(radius, segments);
const material = new THREE.MeshBasicMaterial({ color })
const curve = new THREE.Line(geometry, material);
*/
       this.geom = new THREE.CylinderBufferGeometry(7, 25, 19, 20);
       this.material = new THREE.MeshBasicMaterial( {color: 0x34ebd5} );
       this.solid = new THREE.Mesh(this.geom, this.material);
       this.obj = new THREE.Group();
       this.obj.add(this.solid);

       /*
       this.geom = new THREE.CircleGeometry(attr.R,64);
       if (attr.color != undefined) 
          this.material = new THREE.MeshBasicMaterial({color:attr.color});
       else
       //   this.material = new THREE.MeshBasicMaterial({color:0xff00});
          this.material = new THREE.MeshBasicMaterial();
       this.obj = new THREE.Mesh(this.geom, this.material);
      */
       if (attr.x != undefined && attr.y != undefined && attr.z != undefined)
           this.obj.position.set(attr.x,attr.y,attr.z);
     };
  addToScene(scene) {
    scene.add(this.obj); 
  }
  //From https://stackoverflow.com/a/38306162/932184`
  getPosition() {
    this.geom.computeBoundingBox();
    var center = new THREE.Vector3();
    center = this.geom.boundingBox.getCenter(center);
    var retval = this.obj.localToWorld(center);
    return retval;
  }
  setPos(x,y,z) {
    this.obj.position.set(x,y,z);
    this.obj.updateMatrixWorld();
   }
  //Probably should be common to all solid objects
  rotateX(rad) {
    this.obj.rotation.x = rad;
    this.obj.updateMatrixWorld();
  };
  rotateY(rad) {
    this.obj.rotation.y = rad;
    this.obj.updateMatrixWorld();
  };
  rotateZ(rad) {
    this.obj.rotation.z += rad;
    this.obj.updateMatrixWorld();
  };
 getCurrentVertexPositions() {
    var newverts = new Array();
    for (var i =0; i< this.geom.vertices.length;i++) {
          newverts.push(this.solid.localToWorld(this.solid.geometry.vertices[i].clone()));
   }
   return newverts;
 }

 };

//USe this pattern http://jsfiddle.net/w67tzfhx/ 
//https://threejs.org/docs/#manual/en/introduction/How-to-update-things
  class DynamicLine {

    constructor(attr) {

      this.fixedPt = attr.fixedPt.clone();
      this.currEnd = attr.initialEnd.clone();
      this.maxEnd= attr.maxEnd;
      this.MAX_POINTS = 500;
      this.seg = this.maxEnd.distanceTo(this.fixedPt)/this.MAX_POINTS;
      var actual = (this.currEnd.distanceTo(this.fixedPt)/this.seg);
      var floor = Math.floor(actual);
      this.dir = new THREE.Vector3(this.currEnd.x-this.fixedPt.x,this.currEnd.y-this.fixedPt.y,this.currEnd.z-this.fixedPt.z).normalize();

      if (floor<actual) this.currCount = floor+1;
      else this.currCount= floor;

      if (this.fixedPt.distanceTo(this.currEnd)==0) return;

      // geometry
      this.geom = new THREE.BufferGeometry();

      // attributes
      this.positions = new Float32Array( this.MAX_POINTS * 3 ); // 3 vertices per point
      this.geom.setAttribute( 'position', new THREE.BufferAttribute( this.positions, 3 ) );

      // draw range
      this.geom.setDrawRange( 0, this.currCount);

      const positions = this.geom.attributes.position.array;

      var x, y, z, index;
      index = 0;
      var vec = this.fixedPt.clone();

      for (var i=0;i<this.currCount-1;i++) {

          positions[ index ++ ] = vec.x;
          positions[ index ++ ] = vec.y;
          positions[ index ++ ] = vec.z;
          vec = vec.addScaledVector(this.dir,this.seg);
       };
       vec = this.currEnd;
       positions[ index ++ ] = vec.x;
       positions[ index ++ ] = vec.y;
       positions[ index ++ ] = vec.z;
          

      // material
      this.material = new THREE.LineBasicMaterial( { color: 0xff0000 } );

      // line
      this.obj = new THREE.Line( this.geom,  this.material);

    };
    addToScene(scene) {
       scene.add(this.obj); 
    };

    updateLine(dl) {

       const positions = this.obj.geometry.attributes.position.array;
       var index,vec,extension;

       extension  = dl;

       if (dl==0) return 0;
       var currLength= this.currEnd.distanceTo(this.fixedPt);
       if (currLength+dl <= 0) return 0;
       var newLength = currLength+dl;
       if (newLength > this.MAX_POINTS*this.seg) return 0;

       var newCount =  Math.ceil(newLength/this.seg);
       this.currEnd = this.fixedPt.clone().addScaledVector(this.dir,newLength);

       //Case 1: dl > 0
       //Here if newCount == this.currCount then we need to update the last point in the array to this.currEnd
       //If newCount > this.currCount then we need to set this.currCount through (newCount-1) indices
       //with corresp this.seg multiples; and set newCount index to this.currEnd


        if (dl > 0) {

         vec = this.fixedPt.clone();
         index = this.currCount*3;
         while (newCount > this.currCount) {
           vec = vec.addScaledVector(this.dir,this.currCount*this.seg);
           positions[index-3] = vec.x;
           positions[index-2] = vec.y;
           positions[index-1] = vec.z;
           this.currCount++;
           index = this.currCount*3;
         }
         vec = this.currEnd;
         positions[ index-3 ] = vec.x;
         positions[ index-2 ] = vec.y;
         positions[ index-1 ] = vec.z;
       }
        
       //Case 2: dl < 0
       //Here if newCount == this.currCount then we need to update the last point in the array to this.currEnd
       // If newCount < this.currCount then we need to set this.currCount to newCount and update the newCount index to this.currEnd 

       if (dl < 0) {
           index = newCount*3; 
           vec = this.currEnd;
           positions[ index-3 ] = vec.x;
           positions[ index-2 ] = vec.y;
           positions[ index-1 ] = vec.z;
           this.currCount = newCount;
        }

       /*
       var this.currCount =  Math.ceil(newLength/this.seg);
       var index=0;
       for (var i=0;i<this.currCount-1;i++) {
          positions[ index ++ ] = vec.x;
          positions[ index ++ ] = vec.y;
          positions[ index ++ ] = vec.z;
          vec = vec.addScaledVector(this.dir,this.seg);
       };
       vec = this.currEnd;
       positions[ index ++ ] = vec.x;
       positions[ index ++ ] = vec.y;
       positions[ index ++ ] = vec.z;

      this.obj.geometry.setDrawRange( 0, this.currCount);
      */

      this.obj.geometry.setDrawRange( 0, this.currCount);
      this.obj.geometry.attributes.position.needsUpdate = true;
      this.obj.geometry.computeBoundingBox();
      this.obj.geometry.computeBoundingSphere();
      //console.log("end",this.currEnd);

      return extension;
    };

  };

 

/* Utils */
  //Arbitrary rotations 
  //From https://stackoverflow.com/a/11060965/932184
  // Rotate an object around an arbitrary axis in object space

    function rotateAroundObjectAxis(object, axis, radians) {
    var rotObjectMatrix;
    rotObjectMatrix = new THREE.Matrix4();
    rotObjectMatrix.makeRotationAxis(axis.normalize(), radians);

    // old code for Three.JS pre r54:
    // object.matrix.multiplySelf(rotObjectMatrix);      // post-multiply
    // new code for Three.JS r55+:
    object.matrix.multiply(rotObjectMatrix);

    // old code for Three.js pre r49:
    // object.rotation.getRotationFromMatrix(object.matrix, object.scale);
    // old code for Three.js r50-r58:
    // object.rotation.setEulerFromRotationMatrix(object.matrix);
    // new code for Three.js r59+:
    object.rotation.setFromRotationMatrix(object.matrix);
    };

    // Rotate an object around an arbitrary axis in world space       
   function rotateAroundWorldAxis(object, axis, radians) {
    var rotWorldMatrix;
    rotWorldMatrix = new THREE.Matrix4();
    rotWorldMatrix.makeRotationAxis(axis.normalize(), radians);

    // old code for Three.JS pre r54:
    //  rotWorldMatrix.multiply(object.matrix);
    // new code for Three.JS r55+:
    rotWorldMatrix.multiply(object.matrix);                // pre-multiply

    object.matrix = rotWorldMatrix;

    // old code for Three.js pre r49:
    // object.rotation.getRotationFromMatrix(object.matrix, object.scale);
    // old code for Three.js pre r59:
    // object.rotation.setEulerFromRotationMatrix(object.matrix);
    // code for r59+:
    object.rotation.setFromRotationMatrix(object.matrix);
    };


/* Get the plane3 containing a set of points */

   function getPointAbovePlane(drctn,distance,pt) {
    var ret = new THREE.Vector3(pt);
    ret.addScaledVector(drctn,distance);
    return ret; 
   }

  /* Get tangent to circle parallel to line https://stackoverflow.com/a/47989086/932184 */
  function getTangentPtsOfXYPlaneCircle(dx,dy,cent,rad) {
       var x1,x2,y1,y2,cent,rad,dlen;
       var dir;

      /*
       cent = circ.center();
       rad  = circ.radius;

       dx = (Linept1.x-Linept2.x);
       dy = (Linept1.y-Linept2.y);
      */
       dlen= (dx**2+dy**2)**(1/2);
   
       x1 =  cent.x + rad*dy/dlen;
       y1 =  cent.y - rad*dx/dlen;

       x2 =  cent.x - rad*dy/dlen;
       y2 =  cent.y + rad*dx/dlen;

       return { 
                "p1":new THREE.Vector3(x1,y1,0),
                "p2":new THREE.Vector3(x2,y2,0)
              };
   }
  
  function getLinePlaneIntersection(ln,pln) {
     return pln.intersectLine(ln);
  };

  function getPointDirIntersectingPlane(pt,dir,pln) {
      var pt2 = pt.clone().addScaledVector(dir,1);
      var ln = new THREE.Line3(pt,pt2);
      var ray1 = new THREE.Ray(pt,dir.clone().normalize());
      var ray2 = new THREE.Ray(pt,dir.clone().multiplyScalar(-1).normalize());
      var retval = new THREE.Vector3();
      var target= new THREE.Vector3();
      retval = ray1.intersectPlane(pln,target);
      if (retval==null) retval = ray2.intersectPlane(pln,target);
      return retval;
  }

  
  function init(angle) {
    var angle = angle;

    scene = new THREE.Scene();

    // create a camera, which defines where we're looking at.
    const camera = new THREE.PerspectiveCamera( 20, 500, 0, 500 );

    renderer.setClearColor(new THREE.Color(0x000000));
    renderer.setSize(window.innerWidth/4, window.innerHeight/4);
    // add the output of the renderer to the html element
    document.querySelector("#webgl-output").appendChild(renderer.domElement);

    spotLight = new THREE.SpotLight(0xffffff);
    spotLight.position.set(0, 0, 900);
    scene.add(spotLight);



    // position and point the camera to the center of the scene
    camera.position.set(0, 0, 900);
    camera.lookAt(scene.position);


    //STEP 0: Convention of directions X : left to right ; Y : bottom to top ; Z : In to Out 
    // length L : dimension along X
    // height H : dimension along Y
    // depth D : dimension along Z
    // LH0 is face with outward normal along positive Z ; LH1 along negative Z 
    // HD0 is face with outward normal along positive X;  HD1 along negative Y


    //STEP 1
    //ADD inclined plane with 60 degree angle and base of length 100
    ip = new InclinedPlane({"L":100,
                                "A1":angle*(Math.PI/180),
                                "D":200,
                                "color":0xFF2222
                               },
                               scene
                               );
    ip.addToScene(scene);


    //STEP 2
    //Add box of size 20x20x20 and place at the centre of inclined surface
    bx = new Box( {"L":20,"H":20,"D":20,"color":0777777, "mass": 20});
    bx.addToScene(scene);
    //Find the point above the incliuned plane : which is the face "HD1" of the inclined plane
    var ptOnIncPlane = ip.getFaceMidp("HD1"); //Get midpt
    var ptAbovePlane = getPointAbovePlanePoint(ptOnIncPlane,ip.getPlane("HD1"), 15 /*10*/);  //Get a point 10 units above midpt of HD1
    bx.setPos(ptAbovePlane.x,ptAbovePlane.y,ptAbovePlane.z); //Set bx there and rotate so its parallel to HD1
    bx.rotateZ(angle*(Math.PI/180));

	//renderer.render( scene, camera );
    //STEP 3
    //Create a second box of same size; which is 35 units off the centre of  HD0, the vertical side of the incline plane
    bx2 = new Box( {"L":20,"H":20,"D":20,"color":0777777, "mass": 20});
    bx2.addToScene(scene);
    var ptOnStrtPlane = ip.getFaceMidp("HD0");
    var ptRightPlane = getPointAbovePlanePoint(ptOnStrtPlane,ip.getPlane("HD0"), /* 35 */ 40); 
    bx2.setPos(ptRightPlane.x,ptRightPlane.y,ptRightPlane.z);

	//renderer.render( scene, camera );
 

    


    //STEP 4
    // Place a pulley above and to the right of the top edge, perpendicular to XY plane, of the inclined plane
    /* Get the top point of the leading XY-plane face if the inclined plane*/
    var iPverts = ip.getFaceVerts("LH0");
    var topPoint;
    for (var ii=0;ii < iPverts.length; ii++) 
         if (iPverts[ii].y > 0) topPoint = iPverts[ii];
    
    
    //Place a pulley a little above and to the right of this top point
    var plly_centre = new THREE.Vector3(topPoint.x+20,topPoint.y+20,topPoint.z-100);
    var plly = new Pulley({"R":15,
                           "x":plly_centre.x, //to the right by more than the radius of the pulley
                           "y":plly_centre.y,  //a little above
                           "z":plly_centre.z //The front face is at Z=0; back face is Z=-200; so we want it at the mid point
                          });

     plly.addToScene(scene);
	//renderer.render( scene, camera );

    //STEP 5
    //Locate where to place the "rope" connecting the pulley to the block on ip's HD1


    var ipSlope_dy = Math.sin(angle*(Math.PI/180)); 
    var ipSlope_dx = Math.cos(angle*(Math.PI/180)); 
    //tgtToPulley will hold the pulley points where the circle's tangents parallel to inclined plane LD0
    //and in the pulley's plane meet the circle
    var tgtToPulley = getTangentPtsOfXYPlaneCircle(ipSlope_dx,ipSlope_dy,plly_centre, 20 /*15*/) ;
    tgtToPulley.p1.z = tgtToPulley.p2.z = plly_centre.z;
    //One of tgtToPulley.p1 and tgtToPulley.p2 needs to be connected to the box bx on its HD0 face.
  
    var bxpl = bx.getPlane("HD0");
	//renderer.render( scene, camera );
 
    console.log("tgtPts",tgtToPulley);
    console.log("bxpl",bxpl);


    //pp1: Where does the tangent passing through tgtToPulley.p1 meet the box's HD0 face?
    var pp1 = getPointDirIntersectingPlane(tgtToPulley.p1,new THREE.Vector3(ipSlope_dx,ipSlope_dy,0).normalize(),bxpl);
    //Where does the tangent passing through tgtToPulley.p1 meet the box's HD0 face?
    var pp2 = getPointDirIntersectingPlane(tgtToPulley.p2,new THREE.Vector3(ipSlope_dx,ipSlope_dy,0).normalize(),bxpl);

    console.log("pp1",pp1);
    console.log("pp2",pp2);

    var boxPoint;
    var ropeDir, maxRopeLen;

    //The correct tangent to use is the one with the higher Y coordinate!
    if (pp1.y > pp2.y) {
            boxPoint=pp1;
            pulleyPoint = tgtToPulley.p1;
    }
    else {
            boxPoint = pp2;
            pulleyPoint = tgtToPulley.p2;
    }
    boxPoint.z = plly_centre.z
    ropeDir = new THREE.Vector3(boxPoint.x-pulleyPoint.x,boxPoint.y-pulleyPoint.y,boxPoint.z-pulleyPoint.z).normalize();

    //To get rope length figure out distance between pulleyPoint and base plane of inclined plane (LD1)
    var ipbase = ip.getPlane("LD1");
    pp1 = getPointDirIntersectingPlane(pulleyPoint,new THREE.Vector3(ropeDir.x,ropeDir.y,ropeDir.z).normalize(),ipbase);
    maxRopeLen = pulleyPoint.distanceTo(pp1);

    //Now we need to connect pulleyPoint and boxPoint using a dynamicLine which can grow and shrink at the box
    //point when the box respectively moves down and up the inclined plane.

    
    var ipL = new DynamicLine({"fixedPt":   pulleyPoint.clone(), 
                              "maxEnd" :    pp1,
                              "initialEnd": boxPoint.clone()});
    ipL.addToScene(scene);
    
    //STEP 6
    //Locate where to place the "rope" connecting the pulley to the block on ip's HD0

    var bxpl2 = bx2.getPlane("LD0");
    ipSlope_dy = 1; 
    ipSlope_dx = 0; 
    tgtToPulley = getTangentPtsOfXYPlaneCircle(ipSlope_dx,ipSlope_dy,plly_centre, 20 /*15*/) ;
    tgtToPulley.p1.z = tgtToPulley.p2.z = plly_centre.z;

    //pp1: Where does the tangent passing through tgtToPulley.p1 meet the box's HD0 face?
    pp1 = getPointDirIntersectingPlane(tgtToPulley.p1,new THREE.Vector3(ipSlope_dx,ipSlope_dy,0).normalize(),bxpl2);
    //Where does the tangent passing through tgtToPulley.p1 meet the box's HD0 face?
    pp2 = getPointDirIntersectingPlane(tgtToPulley.p2,new THREE.Vector3(ipSlope_dx,ipSlope_dy,0).normalize(),bxpl2);

    //One of pp1 and pp2 is the right one : the one with the higher X coordinate 
    if (pp2.x<pp1.x ) {
            boxPoint=pp1;
            pulleyPoint = tgtToPulley.p1;
    }
    else {
            boxPoint = pp2;
            pulleyPoint = tgtToPulley.p2;
    }
    boxPoint.z = plly_centre.z
    var ropeDir2 = new THREE.Vector3(boxPoint.x-pulleyPoint.x,boxPoint.y-pulleyPoint.y,boxPoint.z-pulleyPoint.z).normalize();

    //To get rope length figure out distance between pulleyPoint and base plane of inclined plane (LD1)
    ipbase = ip.getPlane("LD1");
    pp1 = getPointDirIntersectingPlane(pulleyPoint,new THREE.Vector3(ropeDir2.x,ropeDir2.y,ropeDir2.z).normalize(),ipbase);
    maxRopeLen = pulleyPoint.distanceTo(pp1);

    //Now we need to connect pulleyPoint and boxPoint using a dynamicLine which can grow and shrink at the box
    //point when the box respectively moves down and up the inclined plane.

    
    var ipL2 = new DynamicLine({"fixedPt":  pulleyPoint.clone(), 
                              "maxEnd" :    pp1,
                              "initialEnd": boxPoint.clone()});
    ipL2.addToScene(scene);
    

    const controls = new THREE.OrbitControls( camera, renderer.domElement );
    controls.update();


    var pos_bx2 ;
    var pos_bx ;
    var newpos_bx2;
    var newpos_bx ;
    var rope1Motion, rope2Motion;
    //render the scene
    sica = setInterval(controls.update, 0)
    exit = false;
    function animate() {
	id = requestAnimationFrame( animate );
        if(exit == false) {
        //Motion
	plly.rotateX(0.15)
        rope2Motion=ipL2.updateLine(0.15);
        rope1Motion=ipL.updateLine(-0.15);

        pos_bx2 = bx2.getPosition().clone();
        pos_bx = bx.getPosition().clone();
        if (rope2Motion) 
            newpos_bx2 = pos_bx2.addScaledVector(ropeDir2,rope2Motion);
        else {
            exit = true
        }
        if (rope1Motion) 
            newpos_bx = pos_bx.addScaledVector(ropeDir,rope1Motion);
        else {
            exit = true
        }
        if(exit == false) {
             // Only do this if exit is false
             bx.setPos(newpos_bx.x,newpos_bx.y,newpos_bx.z);
             bx2.setPos(newpos_bx2.x,newpos_bx2.y,newpos_bx2.z);
        }
        //console.log("rotate");
        //required if controls.enableDamping or controls.autoRotate are set to true
	renderer.render( scene, camera );
      }
    }
    siai = setInterval(function() {
        if(schange == true) {
            animate();
            schange = false;
        }
    }, 0)
  console.log( THREE.REVISION );

}

// Projects a force into its horizontal and vertical components
function project(angle, force) {
    return new THREE.Vector3(force*Math.cos(angle), force*Math.sin(angle), 0)
}

function empty(elem) {
    while (elem.lastChild) elem.removeChild(elem.lastChild);
}

function cleanState() {
    cancelAnimationFrame(id);// Stop the animation
    try {
        renderer.domElement.addEventListener('dblclick', null, false); //remove listener to render
        scene = undefined;
        projector = undefined;
        camera = undefined;
        controls = undefined;
        empty(document.getElementById("webgl-output"));
        clearInterval(sica)
        clearInterval(siai)

    }
    catch {}
}



setInterval(function() {
    if(exit == true) {
        running = false;
    }
}, 0)













// Pause Code
var paused = false;
var schange = true;
setInterval(function() {
    if(paused == true) {
        cancelAnimationFrame(id);
    }
}, 0);

function pauseCode(e) { 
    if(paused == false) {
        paused = true;
        running = false;
        e.innerHTML = "Unpause Code"
        return
    }
    else {
        paused = false;
        running = true;
        schange = true;
        e.innerHTML = "Pause Code"
        return
    }
}
