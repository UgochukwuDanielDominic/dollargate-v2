from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os, uuid, httpx, enum

# ── CONFIG ──────────────────────────────────────────────────────────
DATABASE_URL    = os.getenv("DATABASE_URL", "sqlite:///./dollargate.db")
SECRET_KEY      = os.getenv("SECRET_KEY", "dollargate-secret-key-change-in-prod-2025")
ALGORITHM       = "HS256"
ACCESS_EXPIRE   = 60
REFRESH_EXPIRE  = 60 * 24 * 7
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "sk_test_your_key_here")
FRONTEND_URL    = os.getenv("FRONTEND_URL", "https://dollargate-shop.netlify.app")

# ── DB ──────────────────────────────────────────────────────────────
engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

# ── ENUMS ───────────────────────────────────────────────────────────
class OrderStatus(str, enum.Enum):
    pending="pending"; confirmed="confirmed"; shipped="shipped"; delivered="delivered"; cancelled="cancelled"

class PaymentMethod(str, enum.Enum):
    paystack="paystack"; bank_transfer="bank_transfer"; cash_on_delivery="cash_on_delivery"

class PaymentStatus(str, enum.Enum):
    pending="pending"; paid="paid"; failed="failed"

# ── MODELS ──────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id=Column(Integer,primary_key=True,index=True); name=Column(String,nullable=False)
    email=Column(String,unique=True,index=True,nullable=False); phone=Column(String,nullable=True)
    password=Column(String,nullable=False); is_admin=Column(Boolean,default=False)
    is_active=Column(Boolean,default=True); created_at=Column(DateTime,default=datetime.utcnow)
    orders=relationship("Order",back_populates="user")

class Category(Base):
    __tablename__ = "categories"
    id=Column(Integer,primary_key=True,index=True); name=Column(String,unique=True,nullable=False)
    slug=Column(String,unique=True,nullable=False); products=relationship("Product",back_populates="category")

class Product(Base):
    __tablename__ = "products"
    id=Column(Integer,primary_key=True,index=True); name=Column(String,nullable=False)
    brand=Column(String,nullable=False); description=Column(Text,nullable=True)
    price=Column(Float,nullable=False); original_price=Column(Float,nullable=True)
    image_url=Column(String,nullable=True); tag=Column(String,nullable=True)
    stock=Column(Integer,default=10); is_active=Column(Boolean,default=True)
    category_id=Column(Integer,ForeignKey("categories.id")); created_at=Column(DateTime,default=datetime.utcnow)
    category=relationship("Category",back_populates="products"); order_items=relationship("OrderItem",back_populates="product")

class Order(Base):
    __tablename__ = "orders"
    id=Column(Integer,primary_key=True,index=True)
    reference=Column(String,unique=True,default=lambda:f"DG-{uuid.uuid4().hex[:8].upper()}")
    user_id=Column(Integer,ForeignKey("users.id"),nullable=True)
    customer_name=Column(String,nullable=False); customer_email=Column(String,nullable=False)
    customer_phone=Column(String,nullable=False); address=Column(Text,nullable=False)
    city=Column(String,nullable=False); state=Column(String,nullable=False)
    total=Column(Float,nullable=False)
    payment_method=Column(SQLEnum(PaymentMethod),default=PaymentMethod.paystack)
    payment_status=Column(SQLEnum(PaymentStatus),default=PaymentStatus.pending)
    status=Column(SQLEnum(OrderStatus),default=OrderStatus.pending)
    paystack_ref=Column(String,nullable=True); notes=Column(Text,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)
    user=relationship("User",back_populates="orders"); items=relationship("OrderItem",back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_items"
    id=Column(Integer,primary_key=True,index=True); order_id=Column(Integer,ForeignKey("orders.id"))
    product_id=Column(Integer,ForeignKey("products.id")); quantity=Column(Integer,default=1)
    price=Column(Float,nullable=False); order=relationship("Order",back_populates="items")
    product=relationship("Product",back_populates="order_items")

class Settings(Base):
    __tablename__ = "settings"
    id=Column(Integer,primary_key=True,index=True); key=Column(String,unique=True,nullable=False)
    value=Column(Text,nullable=True)

Base.metadata.create_all(bind=engine)

# ── AUTH HELPERS ────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

def hash_pw(pw): return pwd_ctx.hash(pw)
def verify_pw(pw, h): return pwd_ctx.verify(pw, h)
def make_token(data, minutes):
    p = {**data, "exp": datetime.utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    if not creds: raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload["sub"])
    except: raise HTTPException(401, "Invalid token")
    u = db.query(User).filter(User.id==uid, User.is_active==True).first()
    if not u: raise HTTPException(401, "User not found")
    return u

def admin_only(u: User = Depends(get_user)):
    if not u.is_admin: raise HTTPException(403, "Admin only")
    return u

def optional_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    if not creds: return None
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload["sub"])
        return db.query(User).filter(User.id==uid, User.is_active==True).first()
    except: return None

# ── SCHEMAS ─────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    name: str; email: EmailStr; phone: Optional[str]=None; password: str

class LoginIn(BaseModel):
    email: EmailStr; password: str

class ProductIn(BaseModel):
    name: str; brand: str; description: Optional[str]=None; price: float
    original_price: Optional[float]=None; image_url: Optional[str]=None
    tag: Optional[str]=None; stock: int=10; category_id: int

class ProductUpdate(BaseModel):
    name: Optional[str]=None; brand: Optional[str]=None; description: Optional[str]=None
    price: Optional[float]=None; original_price: Optional[float]=None
    image_url: Optional[str]=None; tag: Optional[str]=None
    stock: Optional[int]=None; is_active: Optional[bool]=None; category_id: Optional[int]=None

class OrderItemIn(BaseModel):
    product_id: int; quantity: int

class OrderIn(BaseModel):
    customer_name: str; customer_email: EmailStr; customer_phone: str
    address: str; city: str; state: str
    payment_method: PaymentMethod; notes: Optional[str]=None
    items: List[OrderItemIn]

class OrderStatusIn(BaseModel):
    status: OrderStatus

class CategoryIn(BaseModel):
    name: str; slug: str

class SettingIn(BaseModel):
    key: str; value: str

# ── APP ─────────────────────────────────────────────────────────────
app = FastAPI(title="DollarGate API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── SEED ────────────────────────────────────────────────────────────
@app.on_event("startup")
def seed():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email=="admin@dollargate.com").first():
            db.add(User(name="DollarGate Admin",email="admin@dollargate.com",password=hash_pw("admin1234"),is_admin=True))
        cats = [("Watches","watches"),("Sunglasses","sunglasses"),("Eyeglasses","eyeglasses")]
        cat_map = {}
        for name,slug in cats:
            c = db.query(Category).filter(Category.slug==slug).first()
            if not c:
                c=Category(name=name,slug=slug); db.add(c); db.flush()
            cat_map[slug] = c.id
        sample = [
            {"name":"Chronograph Elite","brand":"Aurum Watches","price":89000,"original_price":120000,"category":"watches","tag":"New In","stock":8,"image_url":"https://images.unsplash.com/photo-1547996160-81dfa63595aa?w=500&q=80","description":"Swiss-inspired movement with sapphire-coated crystal face and genuine leather strap."},
            {"name":"Royal Oak Day-Date","brand":"Prestige Timepieces","price":145000,"original_price":195000,"category":"watches","tag":"Sale","stock":3,"image_url":"https://images.unsplash.com/photo-1523170335258-f5ed11844a49?w=500&q=80","description":"Day-date complication with gold-toned stainless case and jubilee bracelet."},
            {"name":"Submariner Sport","brand":"Aurum Watches","price":72000,"original_price":95000,"category":"watches","tag":"Sale","stock":5,"image_url":"https://images.unsplash.com/photo-1600080972464-8e5f35f63d08?w=500&q=80","description":"200m water resistance, unidirectional rotating bezel, luminous indices."},
            {"name":"Pilot Classic","brand":"Heritage Time","price":54000,"original_price":78000,"category":"watches","tag":None,"stock":6,"image_url":"https://images.unsplash.com/photo-1585386959984-a4155224a1ad?w=500&q=80","description":"Aviation-inspired dial with Arabic numerals and aged tan leather."},
            {"name":"Noir Aviator","brand":"DollarGate Edit","price":32000,"original_price":None,"category":"sunglasses","tag":"Bestseller","stock":15,"image_url":"https://images.unsplash.com/photo-1511499767150-a48a237f0083?w=500&q=80","description":"Polarised UV400 lenses in bold aviator frame finished in jet-black titanium."},
            {"name":"Shield Wrap Pro","brand":"DollarGate Edit","price":45000,"original_price":None,"category":"sunglasses","tag":"New In","stock":10,"image_url":"https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=500&q=80","description":"Bold wrap shield design with gradient smoke lenses."},
            {"name":"Gold Acetate Frame","brand":"Optical Luxe","price":28000,"original_price":None,"category":"eyeglasses","tag":"New In","stock":12,"image_url":"https://images.unsplash.com/photo-1612394535053-0bab4fd4f4c8?w=500&q=80","description":"Honey-amber acetate with spring hinges and anti-glare lenses."},
            {"name":"Crystal Clear Round","brand":"Optical Luxe","price":19500,"original_price":None,"category":"eyeglasses","tag":"Bestseller","stock":20,"image_url":"https://images.unsplash.com/photo-1574258495973-f010dfbb5371?w=500&q=80","description":"Minimalist round frames in crystal acetate."},
        ]
        for sp in sample:
            if not db.query(Product).filter(Product.name==sp["name"]).first():
                db.add(Product(name=sp["name"],brand=sp["brand"],price=sp["price"],original_price=sp["original_price"],tag=sp["tag"],stock=sp["stock"],image_url=sp["image_url"],description=sp["description"],category_id=cat_map[sp["category"]]))
        defaults=[("store_name","DollarGate"),("bank_name","Zenith Bank"),("account_number","1234567890"),("account_name","DollarGate Nigeria Ltd"),("delivery_fee","2500"),("whatsapp","+2348000000000")]
        for k,v in defaults:
            if not db.query(Settings).filter(Settings.key==k).first():
                db.add(Settings(key=k,value=v))
        db.commit()
    finally: db.close()

# ── ROUTES ──────────────────────────────────────────────────────────
@app.get("/")
def root(): return {"status":"DollarGate API v2","docs":"/docs"}

@app.get("/health")
def health(): return {"status":"ok"}

@app.post("/auth/register",status_code=201)
def register(data:RegisterIn, db:Session=Depends(get_db)):
    if db.query(User).filter(User.email==data.email).first():
        raise HTTPException(400,"Email already registered")
    u=User(name=data.name,email=data.email,phone=data.phone,password=hash_pw(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"access_token":make_token({"sub":str(u.id)},ACCESS_EXPIRE),"refresh_token":make_token({"sub":str(u.id),"type":"refresh"},REFRESH_EXPIRE),"user":{"id":u.id,"name":u.name,"email":u.email,"is_admin":u.is_admin}}

@app.post("/auth/login")
def login(data:LoginIn, db:Session=Depends(get_db)):
    u=db.query(User).filter(User.email==data.email).first()
    if not u or not verify_pw(data.password,u.password): raise HTTPException(401,"Invalid credentials")
    if not u.is_active: raise HTTPException(403,"Account disabled")
    return {"access_token":make_token({"sub":str(u.id)},ACCESS_EXPIRE),"refresh_token":make_token({"sub":str(u.id),"type":"refresh"},REFRESH_EXPIRE),"user":{"id":u.id,"name":u.name,"email":u.email,"is_admin":u.is_admin}}

@app.get("/auth/me")
def me(u:User=Depends(get_user)): return {"id":u.id,"name":u.name,"email":u.email,"phone":u.phone,"is_admin":u.is_admin}

@app.get("/categories")
def categories(db:Session=Depends(get_db)): return db.query(Category).all()

@app.post("/admin/categories",status_code=201)
def add_category(data:CategoryIn, db:Session=Depends(get_db), _=Depends(admin_only)):
    c=Category(name=data.name,slug=data.slug); db.add(c); db.commit(); db.refresh(c); return c

@app.get("/products")
def products(category:Optional[str]=None,tag:Optional[str]=None,search:Optional[str]=None,skip:int=0,limit:int=50,db:Session=Depends(get_db)):
    q=db.query(Product).filter(Product.is_active==True)
    if category: q=q.join(Category).filter(Category.slug==category)
    if tag: q=q.filter(Product.tag==tag)
    if search: q=q.filter(Product.name.ilike(f"%{search}%"))
    return [fmt_p(p) for p in q.offset(skip).limit(limit).all()]

@app.get("/products/{pid}")
def product(pid:int, db:Session=Depends(get_db)):
    p=db.query(Product).filter(Product.id==pid,Product.is_active==True).first()
    if not p: raise HTTPException(404,"Not found")
    return fmt_p(p)

@app.post("/admin/products",status_code=201)
def add_product(data:ProductIn, db:Session=Depends(get_db), _=Depends(admin_only)):
    p=Product(**data.dict()); db.add(p); db.commit(); db.refresh(p); return fmt_p(p)

@app.put("/admin/products/{pid}")
def upd_product(pid:int,data:ProductUpdate, db:Session=Depends(get_db), _=Depends(admin_only)):
    p=db.query(Product).filter(Product.id==pid).first()
    if not p: raise HTTPException(404,"Not found")
    for k,v in data.dict(exclude_unset=True).items(): setattr(p,k,v)
    db.commit(); db.refresh(p); return fmt_p(p)

@app.delete("/admin/products/{pid}")
def del_product(pid:int, db:Session=Depends(get_db), _=Depends(admin_only)):
    p=db.query(Product).filter(Product.id==pid).first()
    if not p: raise HTTPException(404,"Not found")
    p.is_active=False; db.commit(); return {"message":"Removed"}

@app.post("/orders",status_code=201)
def create_order(data:OrderIn, db:Session=Depends(get_db), u=Depends(optional_user)):
    total=0; items_data=[]
    for item in data.items:
        p=db.query(Product).filter(Product.id==item.product_id,Product.is_active==True).first()
        if not p: raise HTTPException(404,f"Product {item.product_id} not found")
        if p.stock<item.quantity: raise HTTPException(400,f"Low stock: {p.name}")
        total+=p.price*item.quantity; items_data.append((p,item.quantity))
    fee=db.query(Settings).filter(Settings.key=="delivery_fee").first()
    total+=float(fee.value) if fee else 2500
    o=Order(user_id=u.id if u else None,customer_name=data.customer_name,customer_email=data.customer_email,customer_phone=data.customer_phone,address=data.address,city=data.city,state=data.state,payment_method=data.payment_method,notes=data.notes,total=total)
    db.add(o); db.flush()
    for p,qty in items_data:
        db.add(OrderItem(order_id=o.id,product_id=p.id,quantity=qty,price=p.price)); p.stock-=qty
    db.commit(); db.refresh(o)
    res=fmt_o(o)
    if data.payment_method==PaymentMethod.paystack:
        res["paystack_amount"]=int(total*100)
        res["paystack_email"]=data.customer_email
        res["paystack_ref"]=o.reference
    return res

@app.get("/orders/track/{ref}")
def track(ref:str, db:Session=Depends(get_db)):
    o=db.query(Order).filter(Order.reference==ref).first()
    if not o: raise HTTPException(404,"Order not found")
    return fmt_o(o)

@app.post("/orders/{ref}/verify")
async def verify(ref:str, db:Session=Depends(get_db)):
    o=db.query(Order).filter(Order.reference==ref).first()
    if not o: raise HTTPException(404,"Not found")
    async with httpx.AsyncClient() as client:
        r=await client.get(f"https://api.paystack.co/transaction/verify/{ref}",headers={"Authorization":f"Bearer {PAYSTACK_SECRET}"})
    d=r.json()
    if d.get("data",{}).get("status")=="success":
        o.payment_status=PaymentStatus.paid; o.status=OrderStatus.confirmed; db.commit()
        return {"verified":True}
    return {"verified":False}

@app.get("/admin/orders")
def admin_orders(status:Optional[str]=None,payment_status:Optional[str]=None,skip:int=0,limit:int=50,db:Session=Depends(get_db),_=Depends(admin_only)):
    q=db.query(Order)
    if status: q=q.filter(Order.status==status)
    if payment_status: q=q.filter(Order.payment_status==payment_status)
    return [fmt_o(o) for o in q.order_by(Order.created_at.desc()).offset(skip).limit(limit).all()]

@app.get("/admin/orders/{oid}")
def admin_order(oid:int, db:Session=Depends(get_db), _=Depends(admin_only)):
    o=db.query(Order).filter(Order.id==oid).first()
    if not o: raise HTTPException(404,"Not found")
    return fmt_o(o)

@app.put("/admin/orders/{oid}/status")
def upd_order(oid:int,data:OrderStatusIn, db:Session=Depends(get_db), _=Depends(admin_only)):
    o=db.query(Order).filter(Order.id==oid).first()
    if not o: raise HTTPException(404,"Not found")
    o.status=data.status; db.commit(); return {"status":data.status}

@app.get("/admin/customers")
def customers(skip:int=0,limit:int=50, db:Session=Depends(get_db), _=Depends(admin_only)):
    return [{"id":u.id,"name":u.name,"email":u.email,"phone":u.phone,"is_active":u.is_active,"created_at":u.created_at.isoformat(),"order_count":len(u.orders)} for u in db.query(User).filter(User.is_admin==False).offset(skip).limit(limit).all()]

@app.put("/admin/customers/{uid}/toggle")
def toggle_customer(uid:int, db:Session=Depends(get_db), _=Depends(admin_only)):
    u=db.query(User).filter(User.id==uid).first()
    if not u: raise HTTPException(404,"Not found")
    u.is_active=not u.is_active; db.commit(); return {"is_active":u.is_active}

@app.get("/admin/analytics")
def analytics(db:Session=Depends(get_db), _=Depends(admin_only)):
    revenue=sum(o.total for o in db.query(Order).filter(Order.payment_status==PaymentStatus.paid).all())
    return {
        "total_revenue":revenue,"revenue_formatted":f"₦{revenue:,.0f}",
        "total_orders":db.query(Order).count(),
        "total_products":db.query(Product).filter(Product.is_active==True).count(),
        "total_customers":db.query(User).filter(User.is_admin==False).count(),
        "pending_orders":db.query(Order).filter(Order.status==OrderStatus.pending).count(),
        "low_stock":[{"id":p.id,"name":p.name,"stock":p.stock} for p in db.query(Product).filter(Product.stock<=3,Product.is_active==True).all()],
        "recent_orders":[fmt_o(o) for o in db.query(Order).order_by(Order.created_at.desc()).limit(5).all()],
    }

@app.get("/admin/settings")
def get_settings(db:Session=Depends(get_db), _=Depends(admin_only)):
    return {s.key:s.value for s in db.query(Settings).all()}

@app.put("/admin/settings")
def upd_settings(data:List[SettingIn], db:Session=Depends(get_db), _=Depends(admin_only)):
    for item in data:
        s=db.query(Settings).filter(Settings.key==item.key).first()
        if s: s.value=item.value
        else: db.add(Settings(key=item.key,value=item.value))
    db.commit(); return {"message":"Saved"}

def fmt_p(p):
    return {"id":p.id,"name":p.name,"brand":p.brand,"description":p.description,"price":p.price,"original_price":p.original_price,"image_url":p.image_url,"tag":p.tag,"stock":p.stock,"is_active":p.is_active,"category_id":p.category_id,"category":p.category.name if p.category else None,"created_at":p.created_at.isoformat() if p.created_at else None}

def fmt_o(o):
    return {"id":o.id,"reference":o.reference,"customer_name":o.customer_name,"customer_email":o.customer_email,"customer_phone":o.customer_phone,"address":o.address,"city":o.city,"state":o.state,"total":o.total,"payment_method":o.payment_method,"payment_status":o.payment_status,"status":o.status,"notes":o.notes,"created_at":o.created_at.isoformat() if o.created_at else None,"items":[{"product_id":i.product_id,"name":i.product.name if i.product else None,"quantity":i.quantity,"price":i.price} for i in o.items] if o.items else []}
