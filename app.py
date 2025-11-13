import streamlit as st
import pandas as pd
import hashlib
import uuid
import os

# ---------------------------
# FILE PATHS
# ---------------------------
USERS_FILE = "users.csv"
PRODUCTS_FILE = "products.csv"

# ---------------------------
# LOAD OR INIT CSV FILES
# ---------------------------
def load_data(file, columns):
    if not os.path.exists(file):
        df = pd.DataFrame(columns=columns)
        df.to_csv(file, index=False)
    else:
        df = pd.read_csv(file)
    return df

users_df = load_data(USERS_FILE, ["name", "username", "password", "salt", "role"])
products_df = load_data(PRODUCTS_FILE, ["title", "price", "stock", "description"])

# ---------------------------
# PASSWORD HASHING
# ---------------------------
def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

# ---------------------------
# SAVE DATA
# ---------------------------
def save_users():
    users_df.to_csv(USERS_FILE, index=False)

def save_products():
    products_df.to_csv(PRODUCTS_FILE, index=False)

# ---------------------------
# CREATE USER
# ---------------------------
def create_user(name: str, username: str, password: str, role: str) -> str:
    global users_df
    if username in users_df["username"].values:
        return "Username already exists."
    salt = uuid.uuid4().hex
    hashed = hash_password(password, salt)
    new_user = pd.DataFrame([{
        "name": name,
        "username": username,
        "password": hashed,
        "salt": salt,
        "role": role
    }])
    users_df = pd.concat([users_df, new_user], ignore_index=True)
    save_users()
    return "User created successfully."

# ---------------------------
# ENSURE DEFAULT ADMIN
# ---------------------------
if "sujal_2930" not in users_df["username"].values:
    salt = uuid.uuid4().hex
    hashed = hash_password("sujalani1@@gym", salt)
    default_admin = pd.DataFrame([{
        "name": "Sujal",
        "username": "sujal_2930",
        "password": hashed,
        "salt": salt,
        "role": "admin"
    }])
    users_df = pd.concat([users_df, default_admin], ignore_index=True)
    save_users()

# ---------------------------
# LOGIN VALIDATION
# ---------------------------
def login_user(username: str, password: str):
    user = users_df[users_df["username"] == username]
    if user.empty:
        return None
    user = user.iloc[0]
    if hash_password(password, user["salt"]) == user["password"]:
        return {
            "name": user["name"],
            "username": user["username"],
            "role": user["role"]
        }
    return None

# ---------------------------
# STREAMLIT PAGE
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
        st.warning("Please log in as admin first.")
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
                result = create_user(name.strip(), username.strip(), password, role)
                if "success" in result.lower():
                    st.success(result)
                else:
                    st.error(result)

        st.write("---")
        st.write("### 🧾 Existing Users")
        st.dataframe(users_df[["name", "username", "role"]])

        st.write("---")
        st.write("### 🏋️ Add Product")
        with st.form("add_product_form"):
            title = st.text_input("Product Name")
            price = st.number_input("Price (₹)", min_value=0.0, format="%.2f")
            stock = st.number_input("Stock Quantity", min_value=0, step=1)
            desc = st.text_area("Description")
            submitted = st.form_submit_button("Add Product")
            if submitted:
                new_product = pd.DataFrame([{
                    "title": title.strip(),
                    "price": float(price),
                    "stock": int(stock),
                    "description": desc.strip()
                }])
                global products_df
                products_df = pd.concat([products_df, new_product], ignore_index=True)
                save_products()
                st.success("Product added successfully!")

# ---------------------------
# USER PAGE
# ---------------------------
elif menu == "User":
    st.subheader("🛒 User Shopping Page")

    if not st.session_state.user or st.session_state.user["role"] != "user":
        st.warning("Please log in as user first.")
    else:
        st.success(f"Welcome, {st.session_state.user['name']}")
        st.write("### 💪 Available Gym Products")
        if products_df.empty:
            st.info("No products yet. Admin must add products.")
        else:
            for _, p in products_df.iterrows():
                st.write(f"**{p['title']}** — ₹{p['price']}")
                if p["description"]:
                    st.caption(p["description"])
                st.write(f"Stock: {p['stock']}")
                st.write("---")

# ---------------------------
# ABOUT PAGE
# ---------------------------
elif menu == "About":
    st.header("About This Project")
    st.markdown("""
    **Project:** Gym Accessories Online Store  
    **Features:**
    - Admin/User login with hashed passwords  
    - CSV-based storage using Pandas  
    - Auto-creates default admin (`sujal_2930` / `sujalani1@@gym`)  
    - Admin can add users & products  
    - Users can view available gym products  
    """)
    st.info("Future: Add cart, checkout, analytics dashboard.")
