'use strict';

const asyncHandler = require('../middleware/asyncHandler');
const { ok } = require('../utils/apiResponse');
const studentsRepo = require('../repositories/studentsRepo');
const studentCourseRegistrationsRepo = require('../repositories/studentCourseRegistrationsRepo');
const studentSectionEnrollmentsRepo = require('../repositories/studentSectionEnrollmentsRepo');
const ApiError = require('../utils/ApiError');

const listStudents = asyncHandler(async (req, res) => {
  const { termId, departmentId, academicLevel, page = 1, limit = 50 } = req.query;
  const result = await studentsRepo.list({
    termId: termId ? Number(termId) : null,
    departmentId: departmentId ? Number(departmentId) : null,
    academicLevel: academicLevel ? Number(academicLevel) : null,
    page: Number(page),
    limit: Number(limit),
  });
  return ok(res, result);
});

const getStudent = asyncHandler(async (req, res) => {
  const student = await studentsRepo.findById(req.params.id);
  if (!student) throw ApiError.notFound('Student not found');
  return ok(res, student);
});

const getMyProfile = asyncHandler(async (req, res) => {
  if (!req.user || req.user.role !== 'STUDENT') {
    throw ApiError.forbidden('Only students can access this endpoint');
  }
  const student = await studentsRepo.findByAccountId(req.user.id);
  if (!student) throw ApiError.notFound('Student profile not found');
  return ok(res, student);
});

const getMyRegistrations = asyncHandler(async (req, res) => {
  if (!req.user || req.user.role !== 'STUDENT') {
    throw ApiError.forbidden('Only students can access this endpoint');
  }
  const student = await studentsRepo.findByAccountId(req.user.id);
  if (!student) throw ApiError.notFound('Student profile not found');
  
  const registrations = await studentCourseRegistrationsRepo.listByStudent(student.id);
  return ok(res, registrations);
});

const getMyEnrollments = asyncHandler(async (req, res) => {
  if (!req.user || req.user.role !== 'STUDENT') {
    throw ApiError.forbidden('Only students can access this endpoint');
  }
  const student = await studentsRepo.findByAccountId(req.user.id);
  if (!student) throw ApiError.notFound('Student profile not found');
  
  const enrollments = await studentSectionEnrollmentsRepo.listByStudent(student.id);
  return ok(res, enrollments);
});

const getMyTimetable = asyncHandler(async (req, res) => {
  if (!req.user || req.user.role !== 'STUDENT') {
    throw ApiError.forbidden('Only students can access this endpoint');
  }
  const student = await studentsRepo.findByAccountId(req.user.id);
  if (!student) throw ApiError.notFound('Student profile not found');
  
  // Get published schedule version
  const { query } = require('../db/pool');
  const versionRes = await query(
    `SELECT id FROM schedule_versions WHERE term_id = (SELECT id FROM academic_terms WHERE is_active = true LIMIT 1) AND state = 'PUBLISHED'`
  );
  if (!versionRes.rows.length) {
    return ok(res, { allocations: [], message: 'No published schedule' });
  }
  
  const versionId = versionRes.rows[0].id;
  
  // Get student's active enrollments
  const enrollments = await studentSectionEnrollmentsRepo.listByStudent(student.id);
  const activeEnrollmentSectionIds = enrollments
    .filter(e => e.state === 'ACTIVE')
    .map(e => e.section_id);
  
  if (activeEnrollmentSectionIds.length === 0) {
    return ok(res, { allocations: [], message: 'No active enrollments' });
  }
  
  // Get allocations for published version filtered by student's enrolled sections
  const allocationsRes = await query(
    `SELECT a.*, s.code as section_code, c.code as course_code, c.title as course_title,
            r.code as room_code, r.building as room_building,
            ts.weekday, ts.starts_at, a.ends_at,
            sr.kind as session_kind, ins.full_name as instructor_name
     FROM allocations a
     JOIN sections s ON s.id = a.section_id
     JOIN courses c ON c.id = s.course_id
     JOIN rooms r ON r.id = a.room_id
     JOIN time_slots ts ON ts.id = a.start_slot_id
     JOIN session_requirements sr ON sr.id = a.requirement_id
     JOIN accounts ins ON ins.id = a.instructor_id
     WHERE a.version_id = $1 AND a.section_id = ANY($2::bigint[])
     ORDER BY ts.weekday, ts.starts_at`,
    [versionId, activeEnrollmentSectionIds]
  );
  
  return ok(res, {
    student: { id: student.id, name: student.full_name },
    allocations: allocationsRes.rows,
  });
});

const { validatePassword } = require('../utils/passwordPolicy');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { withTransaction } = require('../db/pool');
const { query } = require('../db/pool');
const auditRepo = require('../repositories/auditRepo');

module.exports = {
  listStudents,
  getStudent,
  getMyProfile,
  getMyRegistrations,
  getMyEnrollments,
  getMyTimetable,
  createStudent: asyncHandler(async (req, res) => {
    const { university_id, full_name, email, department_id, academic_level, password } = req.body;
    
    if (!university_id || !full_name || !email || !department_id || !academic_level || !password) {
      throw ApiError.badRequest('university_id, full_name, email, department_id, academic_level, and password are required');
    }
    
    // Validate password policy
    const { validatePassword } = require('../utils/passwordPolicy');
    const policyResult = validatePassword(password);
    if (!policyResult.valid) {
      throw ApiError.badRequest('Password does not meet policy.', { errors: policyResult.errors });
    }
    
    // Check for duplicate email
    const existingStudentByEmail = await studentsRepo.findByEmail(email);
    if (existingStudentByEmail) {
      throw ApiError.conflict('A student with this email already exists');
    }
    
    // Check for duplicate university_id
    const existingStudentByUniversityId = await studentsRepo.findByUniversityId(university_id);
    if (existingStudentByUniversityId) {
      throw ApiError.conflict('A student with this university ID already exists');
    }
    
    // Check if department exists
    const { query } = require('../db/pool');
    const deptRes = await query('SELECT id FROM departments WHERE id = $1', [department_id]);
    if (!deptRes.rows.length) {
      throw ApiError.badRequest('Invalid department_id');
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    
    const result = await withTransaction(async (client) => {
      // Create account
      const accountRes = await client.query(
        `INSERT INTO accounts (email, full_name, role, state, home_department_id, password_hash, created_by)
         VALUES ($1, $2, 'STUDENT', 'ACTIVE', $2, $3, $4) RETURNING *`,
        [email, full_name, department_id, department_id, passwordHash, department_id]
      );
      
      const account = accountRes.rows[0];
      
      // Create student record
      const studentRes = await client.query(
        `INSERT INTO students (university_id, full_name, email, department_id, academic_level, account_id, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE') RETURNING *`,
        [university_id, full_name, email, department_id, academic_level, account.id]
      );
      
      const student = studentRes.rows[0];
      
      // Audit log
      await auditRepo.record({
        actorAccountId: req.user.id,
        actorEmail: req.user.email,
        action: 'STUDENT_CREATED',
        entityType: 'students',
        entityId: student.id,
        outcome: 'SUCCESS',
        details: { studentId: student.id, accountId: account.id }
      });
      
      return { account, student };
    });
    
    return {
      student: {
        id: result.student.id,
        university_id: result.student.university_id,
        full_name: result.student.full_name,
        email: result.student.email,
        department_id: result.student.department_id,
        academic_level: result.student.academic_level,
        status: result.student.status
      }
    };
  }