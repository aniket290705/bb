import streamlit as st
from pymongo import MongoClient
import hashlib
import uuid

# ---------------------------
# DATABASE CONNECTION (Atlas Cluster)
# ---------------------------
@st.cache_resource
def get_db():
    client = MongoClient(st.secrets["mongo"]["uri"])
    db = client[st.secrets["mongo"]["db"]]
    return db

db = get_db()
users = db["users"]
products = db["products"]

# ---------------------------
# PASSWORD HASHING
# ---------------------------
def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def create_user(name: str, username: str, password: str, role: str) -> str:
    if not username or not password:
        return "Username and password are required."
    if users.find_one({"username": username}):
        return "Username already exists."
    salt = uuid.uuid4().hex
    hashed = hash_password(password, salt)
    users.insert_one({
        "name": name,
        "username": username,
        "password": hashed,
        "salt": salt,
        "role": role
    })
    return "User created successfully."

# ---------------------------
# AUTO-CREATE DEFAULT ADMIN
# ---------------------------
def ensure_default_admin():
    default_user = users.find_one({"username": "sujal_2930"})
    if not default_user:
        salt = uuid.uuid4().hex
        hashed = hash_password("sujalani1@@gym", salt)
        users.insert_one({
            "name": "Sujal",
            "username": "sujal_2930",
            "password": hashed,
            "salt": salt,
            "role": "admin"
        })
        print("✅ Default admin user 'sujal_2930' created.")
    else:
        print("ℹ️ Default admin already exists.")

ensure_default_admin()

# ---------------------------
# LOGIN VALIDATION
# ---------------------------
def login_user(username: str, password: str):
    user = users.find_one({"username": username})
    if not user:
        return None
    if hash_password(password, user["salt"]) == user["password"]:
        return {
            "name": user["name"],
            "username": user["username"],
            "role": user["role"]
        }
    return None

# ---------------------------
# STREAMLIT PAGE SETUP
# ---------------------------
st.set_page_config(page_title="Gym Accessories Store", layout="centered")
st.title("🏋️ Gym Accessories Online Store")

if "user" not in st.session_state:
    st.session_state.user = None

menu = st.sidebar.radio("Navigation", ["Login", "Admin", "User", "About"])

# ---------------------------
# LOGIN PAGE
# ---------------------------
if menu == "Login":
    st.subheader("🔐 Login Page")
    role = st.radio("Select Role", ["user", "admin"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login"):
            user = login_user(username.strip(), password)
            if user and user["role"] == role:
                st.session_state.user = user
                st.success(f"Welcome {user['name']}! Logged in as {role}.")
            else:
                st.error("Invalid credentials or role mismatch.")
    with col2:
        if st.button("Logout"):
            st.session_state.user = None
            st.info("You have been logged out.")

# ---------------------------
# ADMIN PAGE
# ---------------------------
elif menu == "Admin":
    st.subheader("🧑‍💼 Admin Dashboard")

    if not st.session_state.user or st.session_state.user["role"] != "admin":
        st.warning("Please log in as admin first on the Login page.")
    else:
        st.success(f"Logged in as Admin: {st.session_state.user['name']}")

        st.write("### ➕ Create New User")
        with st.form("create_user_form"):
            name = st.text_input("Full Name")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["user", "admin"])
            submit = st.form_submit_button("Create User")
            if submit:
                username = username.strip()
                if not username:
                    st.error("Username cannot be empty.")
                elif not password:
                    st.error("Password cannot be empty.")
                else:
                    result = create_user(name.strip(), username, password, role)
                    if "successfully" in result.lower():
                        st.success(result)
                    else:
                        st.error(result)

        st.write("---")
        st.write("### 🧾 Existing Users (no sensitive data shown):")
        all_users = list(users.find({}, {"password": 0, "salt": 0}))
        if not all_users:
            st.info("No users found.")
        else:
            for u in all_users:
                st.write(f"**{u.get('name','-')}** ({u.get('role','-')}) — `{u.get('username','-')}`")

        st.write("---")
        st.write("### 🏋️ Add Product")
        with st.form("add_product_form"):
            title = st.text_input("Product Name")
            price = st.number_input("Price (₹)", min_value=0.0, format="%.2f")
            stock = st.number_input("Stock Quantity", min_value=0, step=1)
            desc = st.text_area("Description")
            submitted = st.form_submit_button("Add Product")
            if submitted:
                if not title.strip():
                    st.error("Product name cannot be empty.")
                else:
                    products.insert_one({
                        "title": title.strip(),
                        "price": float(price),
                        "stock": int(stock),
                        "description": desc.strip()
                    })
                    st.success("Product added successfully!")

# ---------------------------
# USER PAGE
# ---------------------------
elif menu == "User":
    st.subheader("🛒 User Shopping Page")

    if not st.session_state.user or st.session_state.user["role"] != "user":
        st.warning("Please log in as user first on the Login page.")
    else:
        st.success(f"Welcome, {st.session_state.user['name']}")

        st.write("### 💪 Available Gym Products")
        all_products = list(products.find({}, {"description": 1, "title": 1, "price": 1, "stock": 1}))
        if not all_products:
            st.info("No products yet. Admin must add products.")
        else:
            for p in all_products:
                st.write(f"**{p['title']}** — ₹{p['price']}")
                if p.get("description"):
                    st.caption(p["description"])
                st.write(f"Stock: {p.get('stock', 0)}")
                st.write("---")

# ---------------------------
# ABOUT PAGE
# ---------------------------
elif menu == "About":
    st.header("About This Project")
    st.markdown("""
    **Project:** Gym Accessories Online Store  
    **Features:**
    - Admin and User login system  
    - MongoDB Atlas (Cluster) connection via Streamlit secrets  
    - Auto-creates default admin (`sujal_2930` / `sujalani1@@gym`)  
    - Admin can create users and add products  
    - Users can view available gym products  
    """)
    st.info("Future updates: Add cart, checkout, and analytics dashboard.")
