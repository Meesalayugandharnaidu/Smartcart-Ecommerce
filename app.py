from flask import Flask,render_template,redirect,session,flash,request,jsonify
import mysql.connector
from flask_mail import Mail, Message
import bcrypt
import random
import config
import os
from werkzeug.utils import secure_filename
import razorpay
import traceback
from flask import make_response
from utils.pdf_generator import generate_pdf






#create object
app=Flask(__name__)
#app secret_key
app.secret_key = config.SECRET_KEY

#establish flask to mysql connection
# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)



@app.route('/')
def home():
    return redirect('user/products?category=')

# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ----------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")
    

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']
    
    
    
    #  Check if admin email already exists
    mydb = get_db_connection()
   
    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE Email=%s", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    mydb.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')


    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

   # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP Sent To Your Email!", "Success")
    return redirect('/verify-otp')







# ROUTE 2: DISPLAY OTP PAGE
# --------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")




# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    mydb = get_db_connection()
   
    cursor = mydb.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    mydb.commit()
    cursor.close()
    mydb.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')






# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# ======================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['Email']
    password = request.form['Password']

    # Step 1: Check if admin email exists
    mydb = get_db_connection()
    
    cursor = mydb.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    cursor.close()
    mydb.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin['Password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 5: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['Name']
    session['admin_email'] = admin['Email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')

 #forget passwor-----
@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'GET':
        return render_template("admin/admin_forgot_password.html")

    email = request.form['Email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE Email=%s", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found!", "danger")
        return redirect('/admin-forgot-password')

    # Generate OTP
    import random
    otp = random.randint(100000, 999999)

    # Store OTP & email in session
    session['reset_email'] = email
    session['otp'] = str(otp)

    # In real app send email, but here we flash it
    flash(f"Your OTP is: {otp}", "success")

    return redirect('/admin-verify-otp')

#verify otp
@app.route('/admin-verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():

    if 'reset_email' not in session:
        flash("Unauthorized access!", "danger")
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template("admin/admin_verify_otp.html")

    entered_otp = request.form['OTP']

    if entered_otp == session.get('otp'):
        session.pop('otp', None)   # OTP valid → remove OTP
        return redirect('/admin-reset-password')
    else:
        flash("Invalid OTP! Try again.", "danger")
        return redirect('/admin-verify-otp')


 #create new passowrd

@app.route('/admin-reset-password', methods=['GET', 'POST'])
def admin_reset_password():

    if 'reset_email' not in session:
        flash("Unauthorized access!", "danger")
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template("admin/admin_reset_password.html")

    new_pass = request.form['NewPassword']
    confirm_pass = request.form['ConfirmPassword']

    if new_pass != confirm_pass:
        flash("Passwords do not match!", "danger")
        return redirect('/admin-reset-password')

    hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE admin SET Password=%s WHERE Email=%s",
                   (hashed, session['reset_email']))
    conn.commit()

    cursor.close()
    conn.close()

    session.pop('reset_email', None)

    flash("Updated Successfull! Please login.", "success")
    return redirect('/admin-login')


# ROUTE 6: ADMIN DASHBOARD (PROTECTED ROUTE)
# =========================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])




# ROUTE 6: ADMIN LOGOUT
# ======================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logout Successfully.", "success")
    return redirect('/admin-login')



# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 1: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")

# =================================================================
# ROUTE 2: ADD PRODUCT INTO DATABASE
# =================================================================

@app.route('/admin/add-item', methods=['GET','POST'])
def add_item():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        price = request.form['price']
        quantity = request.form['quantity']
        image_file = request.files['image']

        if image_file.filename == "":
            flash("Please upload a product image!", "danger")
            return redirect('/admin/add-item')

        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO products (name, description, category, price,quantity , image) VALUES (%s, %s, %s, %s,%s, %s)",
            (name, description, category, price, quantity,filename)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Product Added Successfull!", "success")
        return redirect('/admin/add-item')

    # GET request → render form
    return render_template('admin/add_item.html')


# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# ================================================================


#add item 

@app.route('/admin/item-list')
def item_list():
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Fetch products with total sold
    query = """
        SELECT 
            p.product_id,
            p.name,
            p.category,
            p.price,
            p.stock AS remaining_stock,
            p.image,
            COALESCE(SUM(oi.quantity), 0) AS total_sold
        FROM products p
        LEFT JOIN order_items oi ON p.product_id = oi.product_id
        WHERE 1=1
    """
    params = []

    if search:
        query += " AND p.name LIKE %s"
        params.append(f"%{search}%")
    if category_filter:
        query += " AND p.category = %s"
        params.append(category_filter)

    query += " GROUP BY p.product_id ORDER BY p.product_id DESC"

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin/item_list.html', products=products, categories=categories)

# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)






# route-11
#---------------------
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)







# =================================================================
# ROUTE:12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image_name, item_id))
 
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# Route 13: DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check product exists
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        cursor.close()
        conn.close()
        return redirect('/admin/item-list')

    try:
        # Delete from order_items first
        cursor.execute("DELETE FROM order_items WHERE product_id=%s", (item_id,))

        # Then delete from products
        cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
        conn.commit()
        flash("Product deleted permanently!", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Error deleting product: {str(e)}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect('/admin/item-list')

#Admin profile
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, Email=%s, Password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')



# ROUTE: USER REGISTRATION
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')

# ROUTE: USER LOGIN
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')

# ROUTE: USER forget password
# =============================
# USER FORGOT PASSWORD (Generate OTP)
# =============================
@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():
    if request.method == 'GET':
        return render_template("user/user_forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        flash("Email not found!", "danger")
        return redirect('/user-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store OTP and email in session
    session['reset_email'] = email
    session['reset_otp'] = otp


    # Optional: Show OTP on screen for development
    # flash(f"Your OTP is: {otp}", "info") 
    flash(f"Your OTP is: {otp}", "success")
    return redirect('/user-verify-otp')
# =============================
# VERIFY OTP
# =============================
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():
    # Session expired / no email saved
    if 'reset_email' not in session:
        flash("Session expired. Try again.", "danger")
        return redirect('/user-forgot-password')

    # Show OTP page
    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    entered_otp = request.form['otp']

    # Check OTP match
    if str(session['reset_otp']) == entered_otp:
        flash("OTP verified! Please set your new password.", "success")
        return redirect('/user-reset-password')

    flash("Invalid OTP! Try again.", "danger")
    return redirect('/user-verify-otp')



# =============================
# RESET PASSWORD
# =============================
@app.route('/user-reset-password', methods=['GET', 'POST'])
def user_reset_password():

    # Prevent access without OTP verification
    if 'reset_email' not in session:
        flash("Session expired!", "danger")
        return redirect('/user-forgot-password')

    # Show Reset Password page
    if request.method == 'GET':
        return render_template("user/user_reset_password.html")

    # Get new password
    new_pass = request.form['password']
    hashed_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password=%s WHERE email=%s",
                   (hashed_pass.decode('utf-8'), session['reset_email']))

    conn.commit()
    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_email', None)
    session.pop('reset_otp', None)

    flash("Password reset successfully! Please login.", "success")
    return redirect('/user-login')



# ROUTE: USER DASHBOARD
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])
# ROUTE: USER LOGOUT
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logout out successfully!", "success")
    return redirect('/user-login')



# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )
# ROUTE: USER PRODUCT DETAILS PAGE
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)





# ADD ITEM TO CART
@app.route('/user/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Get product (current available stock)
        cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
        product = cursor.fetchone()
        if not product:
            flash("Product not found!", "danger")
            return redirect('/user/products')

        # Correct stock check: if no stock available
        if product['stock'] <= 0:
            flash("Product out of stock!", "warning")
            return redirect(f"/user/product/{product_id}")

        # Check if item already in cart
        cursor.execute(
            "SELECT * FROM cart WHERE user_id=%s AND product_id=%s",
            (session['user_id'], product_id)
        )
        cart_item = cursor.fetchone()

        if cart_item:
            # product['stock'] reflects remaining stock outside cart,
            # so if it's 0 we cannot add more
            if product['stock'] <= 0:
                flash(f"Only {product['stock']} items available!", "warning")
                return redirect(f"/user/product/{product_id}")

            cursor.execute(
                "UPDATE cart SET quantity = quantity + 1 WHERE cart_id=%s",
                (cart_item['cart_id'],)
            )
        else:
            cursor.execute(
                "INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                (session['user_id'], product_id, 1)
            )

        # Reduce product stock by 1
        cursor.execute(
            "UPDATE products SET stock = stock - 1 WHERE product_id=%s",
            (product_id,)
        )

        conn.commit()
        flash(f"{product['name']} added to cart!", "success")
        return redirect(f"/user/product/{product_id}")

    finally:
        cursor.close()
        conn.close()


# VIEW CART
@app.route('/user/cart')
def view_cart():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT c.cart_id, c.product_id, c.quantity,
                   p.name, p.price, p.image, p.stock
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id=%s
        """, (session['user_id'],))
        cart_items = cursor.fetchall()

        # calculate grand total
        grand_total = sum(item['price'] * item['quantity'] for item in cart_items)

        return render_template("user/cart.html", cart=cart_items, grand_total=grand_total)
    finally:
        cursor.close()
        conn.close()


# INCREASE QUANTITY
@app.route('/user/cart/increase/<int:cart_id>')
def increase_quantity(cart_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # fetch cart item
        cursor.execute("SELECT * FROM cart WHERE cart_id=%s", (cart_id,))
        item = cursor.fetchone()
        if not item:
            flash("Cart item not found!", "danger")
            return redirect('/user/cart')

        # fetch product to check available stock
        cursor.execute("SELECT stock, name FROM products WHERE product_id=%s", (item['product_id'],))
        product = cursor.fetchone()
        if not product:
            flash("Product not found!", "danger")
            return redirect('/user/cart')

        # if no stock left → cannot increase
        if product['stock'] <= 0:
            flash("No more stock available!", "warning")
            return redirect('/user/cart')

        # increase cart quantity and decrease product stock
        cursor.execute("UPDATE cart SET quantity = quantity + 1 WHERE cart_id=%s", (cart_id,))
        cursor.execute("UPDATE products SET stock = stock - 1 WHERE product_id=%s", (item['product_id'],))

        conn.commit()
        flash(f"Added more {product['name']}!", "success")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()


# DECREASE QUANTITY
@app.route('/user/cart/decrease/<int:cart_id>')
def decrease_quantity(cart_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # fetch cart item
        cursor.execute("SELECT * FROM cart WHERE cart_id=%s", (cart_id,))
        item = cursor.fetchone()
        if not item:
            flash("Cart item not found!", "danger")
            return redirect('/user/cart')

        # If quantity is 1, remove the cart row; otherwise decrement
        if item['quantity'] <= 1:
            cursor.execute("DELETE FROM cart WHERE cart_id=%s", (cart_id,))
        else:
            cursor.execute("UPDATE cart SET quantity = quantity - 1 WHERE cart_id=%s", (cart_id,))

        # Return one unit to product stock
        cursor.execute("UPDATE products SET stock = stock + 1 WHERE product_id=%s", (item['product_id'],))

        conn.commit()
        flash("Item updated!", "success")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()


# REMOVE ITEM
@app.route('/user/cart/remove/<int:cart_id>')
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM cart WHERE cart_id=%s", (cart_id,))
        item = cursor.fetchone()
        if item:
            # Return quantity to stock then remove cart row
            cursor.execute(
                "UPDATE products SET stock = stock + %s WHERE product_id=%s",
                (item['quantity'], item['product_id'])
            )
            cursor.execute("DELETE FROM cart WHERE cart_id=%s", (cart_id,))
            flash("Item removed!", "success")

        conn.commit()
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()
    
    
    
    
    


@app.route("/user/address")
def user_address():
    return render_template("user/address.html")




@app.route("/user/address/save", methods=["POST"])
def save_address():
    # Get all form fields
    name = request.form["name"]
    phone = request.form["phone"]
    pincode = request.form["pincode"]
    state = request.form["state"]
    city = request.form["city"]
    address = request.form["address"]

    # Get user ID from session
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/login")

    # Create cursor
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    sql = """
        INSERT INTO user_address (user_id, name, phone, pincode, state, city, address)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    values = (user_id, name, phone, pincode, state, city, address)

    # Execute SQL insert
    cursor.execute(sql, values)

    # Commit changes
    conn.commit()

    # Close cursor
    cursor.close()

    # Redirect to payment page
    return redirect("/user/pay")



# ROUTE: CREATE RAZORPAY ORDER

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)


# ROUTE: CREATE RAZORPAY ORDER
@app.route('/user/pay')
def user_pay():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.cart_id, c.product_id, c.quantity, p.name, p.price, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = %s
    """, (user_id,))

    cart_items = cursor.fetchall()
    cursor.close()
    conn.close()

    if not cart_items:
        flash("Your cart is empty!", "warning")
        return redirect('/user/cart')

    # Convert Decimal to float for Razorpay
    grand_total = float(sum(item['price'] * item['quantity'] for item in cart_items))

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": int(grand_total * 100),  # Razorpay expects integer in paise
        "currency": "INR",
        "payment_capture": 1
    })

    return render_template(
        "user/payment.html",
        cart=cart_items,
        grand_total=grand_total,
        amount=grand_total,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )


@app.route('/payment-failed')
def payment_failed():
    reason = request.args.get("reason", "Payment was not completed.")

    return render_template(
        "user/payment_failed.html",
        reason=reason
    )

# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Verify Razorpay signature
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']

    # Fetch cart items from DB
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT c.product_id, c.quantity, p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = %s
    """, (user_id,))
    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))
        order_db_id = cursor.lastrowid

        # Insert order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, item['product_id'], item['name'], item['quantity'], item['price']))

        # Clear user's cart in DB
        cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
        conn.commit()

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s", str(e))
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

# Route: success Payment and Store Order
# ------------------------------

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch order
    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=%s AND user_id=%s
    """, (order_db_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # Fetch order items
    cursor.execute("""
        SELECT * FROM order_items WHERE order_id=%s
    """, (order_db_id,))
    items = cursor.fetchall()

    # Fetch user address
    cursor.execute("""
        SELECT name, phone, pincode, state, city, address 
        FROM user_address 
        WHERE user_id=%s 
        ORDER BY id DESC LIMIT 1
    """, (session['user_id'],))
    user_address = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        "user/order_success.html",
        order=order,
        items=items,
        user_address=user_address
    )



@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# GENERATE INVOICE PDF
# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()
    
        # Fetch user address
    cursor.execute("""
        SELECT name, phone, pincode, state, city, address 
        FROM user_address 
        WHERE user_id=%s 
        ORDER BY id DESC LIMIT 1
    """, (session['user_id'],))
    user_address = cursor.fetchone()

    

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order,  user_address = user_address ,items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response


#run cod 
#---------------------
if __name__=="__main__":
    app.run(debug=True)